/// <reference types="@cloudflare/workers-types" />
/// <reference lib="es2021" />
//@ts-check
import { DORM, createClient } from "dormroom";

export { DORM };
export interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  X_REDIRECT_URI: string;
  LOGIN_REDIRECT_URI: string;
  DORM_NAMESPACE: DurableObjectNamespace<DORM>;
}

export const html = (strings: TemplateStringsArray, ...values: any[]) => {
  return strings.reduce(
    (result, str, i) => result + str + (values[i] || ""),
    "",
  );
};

// CORS headers for responses
function getCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

async function generateRandomString(length: number): Promise<string> {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper to extract cookie value
function getCookieValue(
  cookieString: string | null,
  name: string,
): string | null {
  if (!cookieString) return null;
  const matches = cookieString.match(new RegExp(`${name}=([^;]+)`));
  return matches ? decodeURIComponent(matches[1]) : null;
}

// Create a channel ID from two usernames (sorted alphabetically)
function createChannelId(user1: string, user2: string): string {
  return [user1, user2].sort().join(':');
}

const migrations = {
  // initial version
  1: [
    `
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      name TEXT,
      profile_image_url TEXT,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id TEXT NOT NULL,
      login TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      message TEXT NOT NULL
    )
    `,
    `
    CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel_id)
    `
  ],
}

export default {
  fetch: async (request: Request, env: Env, ctx: ExecutionContext) => {
    // Deconstruct Cookies
    const url = new URL(request.url);
    const method = request.method;
    const cookie = request.headers.get("Cookie");
    const xAccessToken = getCookieValue(cookie, "x_access_token");
    const userId = getCookieValue(cookie, "x_user_id");
    const accessToken = xAccessToken || url.searchParams.get("apiKey");

    // Handle CORS preflight requests
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(),
      });
    }

    // Initialize DORM client for user database
    const dbName = url.pathname.startsWith("/admin/")
      ? url.pathname.split("/")[2]
      : undefined;
    const prefix = `/admin/${dbName}`;

    // Initialize DORM client for user database
    const client = createClient({
      doNamespace: env.DORM_NAMESPACE,
      version: "v2", // Version prefix for migrations
      migrations,
      ctx, // Pass execution context for waitUntil
      name: dbName || userId || "anonymous", // Use user ID as database name
    });

    // Handle DB middleware requests (for exploring the DB)
    const middlewareResponse = await client.middleware(request, {
      prefix,
      secret: env.X_CLIENT_SECRET,
    });
    if (middlewareResponse) return middlewareResponse;

    // X Login routes
    if (url.pathname === "/login") {
      const scope = url.searchParams.get("scope");
      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const Location = `https://x.com/i/oauth2/authorize?response_type=code&client_id=${
        env.X_CLIENT_ID
      }&redirect_uri=${encodeURIComponent(
        env.X_REDIRECT_URI,
      )}&scope=${encodeURIComponent(
        scope || "users.read follows.read tweet.read offline.access",
      )}&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

      const headers = new Headers(getCorsHeaders());

      headers.append("Location", Location);

      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=600`,
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=600`,
      );

      return new Response("Redirecting", {
        status: 307,
        headers,
      });
    }

    // X OAuth callback route
    if (url.pathname === "/callback") {
      const urlState = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      const cookieString = request.headers.get("Cookie") || "";

      const stateCookie = getCookieValue(cookieString, "x_oauth_state");
      const codeVerifier = getCookieValue(cookieString, "x_code_verifier");

      // Validate state and code verifier
      if (
        !urlState ||
        !stateCookie ||
        urlState !== stateCookie ||
        !codeVerifier
      ) {
        return new Response(
          `Invalid state or missing code verifier. Session validation failed.`,
          {
            status: 400,
            headers: getCorsHeaders(),
          },
        );
      }

      try {
        // Exchange code for access token
        const tokenResponse = await fetch(
          "https://api.twitter.com/2/oauth2/token",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Authorization: `Basic ${btoa(
                `${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`,
              )}`,
            },
            body: new URLSearchParams({
              code: code || "",
              redirect_uri: env.X_REDIRECT_URI,
              grant_type: "authorization_code",
              code_verifier: codeVerifier,
            }),
          },
        );

        if (!tokenResponse.ok) {
          throw new Error(
            `Twitter API responded with ${
              tokenResponse.status
            }: ${await tokenResponse.text()}`,
          );
        }

        const tokenData: any = await tokenResponse.json();
        const { access_token, refresh_token } = tokenData;

        // Fetch user data to store in the database
        const userResponse = await fetch(
          "https://api.x.com/2/users/me?user.fields=profile_image_url",
          {
            headers: {
              Authorization: `Bearer ${access_token}`,
              "Content-Type": "application/json",
            },
          },
        );

        if (!userResponse.ok) {
          throw new Error(
            `X API error: ${userResponse.status} ${await userResponse.text()}`,
          );
        }

        const userData: any = await userResponse.json();
        const { id, name, username, profile_image_url } = userData.data;

        if (!id) {
          throw new Error(`X API error: no ID found`);
        }

        // Create a client for this specific user
        const userClient = createClient({
          doNamespace: env.DORM_NAMESPACE,
          version: "v2",
          migrations,
          ctx,
          name: String(id),
        });

        // Check if user exists in database
        const existingUser = await userClient.exec(
          "SELECT * FROM users WHERE id = ?",
          id
        ).one().catch(() => null);

        if (existingUser) {
          // Update existing user
          await userClient.exec(
            "UPDATE users SET access_token = ?, refresh_token = ?, name = ?, profile_image_url = ?, last_login = ? WHERE id = ?",
            access_token,
            refresh_token || null,
            name,
            profile_image_url,
            new Date().toISOString(),
            id
          );
        } else {
          // Create new user
          await userClient.exec(
            "INSERT INTO users (id, username, name, profile_image_url, access_token, refresh_token) VALUES (?, ?, ?, ?, ?, ?)",
            id,
            username,
            name,
            profile_image_url,
            access_token,
            refresh_token || null
          );
        }

        const headers = new Headers({
          ...getCorsHeaders(),
          Location: url.origin + (env.LOGIN_REDIRECT_URI || "/"),
        });

        // Set access token cookie and clear temporary cookies
        headers.append(
          "Set-Cookie",
          `x_access_token=${encodeURIComponent(
            access_token,
          )}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_user_id=${encodeURIComponent(
            id,
          )}; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_username=${encodeURIComponent(
            username,
          )}; Path=/; Secure; SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_oauth_state=; Max-Age=0; Path=/`,
        );
        headers.append(
          "Set-Cookie",
          `x_code_verifier=; Max-Age=0; Path=/`,
        );

        return new Response("Redirecting", {
          status: 307,
          headers,
        });
      } catch (error) {
        return new Response(
          html`
            <!DOCTYPE html>
            <html lang="en">
              <head>
                <title>Login Failed</title>
              </head>
              <body>
                <h1>X Login Failed</h1>
                <p>
                  ${error instanceof Error ? error.message : "Unknown error"}
                </p>
                <a href="/">Return to homepage</a>
              </body>
            </html>
          `,
          {
            status: 500,
            headers: {
              "Content-Type": "text/html",
              "Set-Cookie": `x_oauth_state=; Max-Age=0; Path=/, x_code_verifier=; Max-Age=0; Path=/`,
              ...getCorsHeaders(),
            },
          },
        );
      }
    }

    // Logout route
    if (url.pathname === "/logout") {
      // Update last_login in the database if we have the user ID
      if (userId) {
        await client.exec(
          "UPDATE users SET last_login = ? WHERE id = ?",
          new Date().toISOString(),
          userId
        );
      }

      const headers = new Headers({
        Location: "/",
        ...getCorsHeaders(),
      });

      headers.append(
        "Set-Cookie",
        "x_access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_user_id=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_username=; Max-Age=0; Path=/; Secure; SameSite=Lax",
      );

      return new Response("Logging out...", { status: 302, headers });
    }

    // Handle message creation endpoint
    if (url.pathname === "/message" && method === "POST") {
      if (!accessToken || !userId) {
        return new Response("Unauthorized", { 
          status: 401, 
          headers: getCorsHeaders() 
        });
      }

      try {
        // Get current user's username
        const currentUser = await client.exec(
          "SELECT username FROM users WHERE id = ?",
          userId
        ).one();

        if (!currentUser) {
          return new Response("User not found", { 
            status: 404, 
            headers: getCorsHeaders() 
          });
        }

        const currentUsername = currentUser.username as string;

        // Parse request body
        const formData = await request.formData();
        const recipientUsername = formData.get("recipient") as string;
        const messageText = formData.get("message") as string;

        if (!recipientUsername || !messageText) {
          return new Response("Missing recipient or message", { 
            status: 400, 
            headers: getCorsHeaders() 
          });
        }

        // Create channel ID (alphabetically sorted usernames)
        const channelId = createChannelId(currentUsername, recipientUsername);

        // Add message to current user's database
        await client.exec(
          "INSERT INTO messages (channel_id, login, message) VALUES (?, ?, ?)",
          channelId,
          currentUsername,
          messageText
        );

        // Create a client for the recipient
        // We need to find the recipient's ID first
        const recipientId = await client.exec(
          "SELECT id FROM users WHERE username = ?",
          recipientUsername
        ).one().catch(() => null);

        if (recipientId) {
          // Recipient exists in our system, add message to their database too
          const recipientClient = createClient({
            doNamespace: env.DORM_NAMESPACE,
            version: "v2",
            migrations,
            ctx,
            name: String(recipientId.id),
          });

          await recipientClient.exec(
            "INSERT INTO messages (channel_id, login, message) VALUES (?, ?, ?)",
            channelId,
            currentUsername,
            messageText
          );
        }

        // Redirect back to dashboard
        return new Response("Message sent", { 
          status: 302, 
          headers: {
            Location: "/dashboard",
            ...getCorsHeaders()
          }
        });
      } catch (error) {
        return new Response(
          `Error sending message: ${error instanceof Error ? error.message : "Unknown error"}`,
          { status: 500, headers: getCorsHeaders() }
        );
      }
    }

    // Dashboard route - show user profile and messages if logged in
    if (url.pathname === "/dashboard") {
      if (!accessToken || !userId) {
        // Redirect to login if no access token
        return new Response("Redirecting to login...", {
          status: 302,
          headers: {
            Location: "/login",
            ...getCorsHeaders(),
          },
        });
      }

      // Try to get user data from database with matching access_token
      const userData = await client.exec(
        "SELECT * FROM users WHERE id = ? AND access_token = ?",
        userId,
        accessToken
      ).one().catch(() => null);

      if (!userData) {
        return new Response("Redirecting to login...", {
          status: 302,
          headers: { Location: "/login", ...getCorsHeaders() },
        });
      }

      // Get channel ID from URL if provided
      const activeChannel = url.searchParams.get('channel');
      
      // Get all messages grouped by channel
      const channels = await client.exec(
        "SELECT DISTINCT channel_id FROM messages"
      ).toArray();

      let messages = [];
      let otherUsername = "";
      
      if (activeChannel) {
        // Get messages for the selected channel
        messages = await client.exec(
          "SELECT * FROM messages WHERE channel_id = ? ORDER BY created_at ASC",
          activeChannel
        ).toArray();
        
        // Extract the other username from the channel ID
        const channelParts = activeChannel.split(':');
        otherUsername = channelParts[0] === userData.username ? channelParts[1] : channelParts[0];
      }

      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>X Messaging App</title>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <style>
                body { 
                  font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
                  margin: 0; 
                  padding: 0;
                  height: 100vh;
                  display: flex;
                  flex-direction: column;
                }
                header {
                  background: #1DA1F2;
                  color: white;
                  padding: 10px 20px;
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                }
                .profile {
                  display: flex;
                  align-items: center;
                  gap: 10px;
                }
                .profile img {
                  border-radius: 50%;
                  width: 40px;
                  height: 40px;
                }
                .btn {
                  display: inline-block;
                  padding: 8px 16px;
                  background: white;
                  color: #1DA1F2;
                  text-decoration: none;
                  border-radius: 4px;
                  font-weight: bold;
                }
                .container {
                  display: flex;
                  flex: 1;
                  overflow: hidden;
                }
                .sidebar {
                  width: 30%;
                  background: #f5f8fa;
                  border-right: 1px solid #e1e8ed;
                  overflow-y: auto;
                }
                .message-area {
                  width: 70%;
                  display: flex;
                  flex-direction: column;
                  background: #fff;
                }
                .channel {
                  padding: 15px;
                  border-bottom: 1px solid #e1e8ed;
                  cursor: pointer;
                }
                .channel:hover {
                  background: #e8f5fd;
                }
                .channel.active {
                  background: #e8f5fd;
                  border-left: 3px solid #1DA1F2;
                }
                .messages {
                  flex: 1;
                  overflow-y: auto;
                  padding: 20px;
                }
                .message-input {
                  padding: 15px;
                  border-top: 1px solid #e1e8ed;
                }
                .message-form {
                  display: flex;
                  gap: 10px;
                }
                .message-form input[type="text"] {
                  flex: 1;
                  padding: 10px;
                  border: 1px solid #e1e8ed;
                  border-radius: 20px;
                }
                .message-form button {
                  background: #1DA1F2;
                  color: white;
                  border: none;
                  border-radius: 20px;
                  padding: 10px 20px;
                  cursor: pointer;
                }
                .message-bubble {
                  max-width: 70%;
                  padding: 10px 15px;
                  margin-bottom: 10px;
                  border-radius: 18px;
                  position: relative;
                }
                .message-outgoing {
                  background: #1DA1F2;
                  color: white;
                  margin-left: auto;
                  border-bottom-right-radius: 5px;
                }
                .message-incoming {
                  background: #e1e8ed;
                  color: #14171a;
                  margin-right: auto;
                  border-bottom-left-radius: 5px;
                }
                .message-time {
                  font-size: 0.7em;
                  margin-top: 5px;
                  opacity: 0.7;
                }
                .channel-header {
                  padding: 15px;
                  border-bottom: 1px solid #e1e8ed;
                  font-weight: bold;
                  display: flex;
                  justify-content: space-between;
                }
                .new-chat {
                  display: block;
                  margin: 15px;
                  text-align: center;
                  padding: 10px;
                  background: #1DA1F2;
                  color: white;
                  text-decoration: none;
                  border-radius: 4px;
                  font-weight: bold;
                }
                .new-chat-form {
                  padding: 15px;
                  background: #f5f8fa;
                  border-bottom: 1px solid #e1e8ed;
                  display: none;
                }
                .new-chat-form.active {
                  display: block;
                }
                .new-chat-form input {
                  width: 100%;
                  padding: 10px;
                  margin-bottom: 10px;
                  border: 1px solid #e1e8ed;
                  border-radius: 4px;
                }
                .new-chat-form button {
                  width: 100%;
                  padding: 10px;
                  background: #1DA1F2;
                  color: white;
                  border: none;
                  border-radius: 4px;
                  cursor: pointer;
                }
                .empty-state {
                  display: flex;
                  flex-direction: column;
                  align-items: center;
                  justify-content: center;
                  height: 100%;
                  color: #657786;
                  text-align: center;
                  padding: 20px;
                }
                .empty-state svg {
                  width: 80px;
                  height: 80px;
                  margin-bottom: 20px;
                  fill: #657786;
                }
                .empty-state h3 {
                  margin-bottom: 10px;
                }
              </style>
            </head>
            <body>
              <header>
                <div class="profile">
                  <img src="${userData.profile_image_url}" alt="Profile">
                  <div>
                    <strong>${userData.name}</strong>
                  </div>
                </div>
                <a href="/logout" class="btn">Logout</a>
              </header>
              
              <div class="container">
                <div class="sidebar">
                  <a href="#" class="new-chat" id="newChatBtn">New Message</a>
                  
                  <div class="new-chat-form" id="newChatForm">
                    <form action="/message" method="post">
                      <input type="text" name="recipient" placeholder="Enter username" required>
                      <input type="text" name="message" placeholder="Type your message" required>
                      <button type="submit">Start Chat</button>
                    </form>
                  </div>
                  
                  ${channels.length === 0 
                    ? `<div style="padding: 20px; color: #657786; text-align: center;">No conversations yet</div>` 
                    : channels.map(channel => {
                        const channelParts = (channel.channel_id as string).split(':');
                        const otherUser = channelParts[0] === userData.username ? channelParts[1] : channelParts[0];
                        const isActive = activeChannel === channel.channel_id;
                        
                        return `
                          <div class="channel ${isActive ? 'active' : ''}" 
                               onclick="window.location.href='/dashboard?channel=${channel.channel_id}'">
                            <strong>@${otherUser}</strong>
                          </div>
                        `;
                      }).join('')
                  }
                </div>
                
                <div class="message-area">
                  ${activeChannel 
                    ? `
                      <div class="channel-header">
                        <div>Chat with @${otherUsername}</div>
                      </div>
                      
                      <div class="messages">
                        ${messages.length === 0 
                          ? `<div style="text-align: center; color: #657786; padding: 20px;">No messages yet</div>` 
                          : messages.map(msg => {
                              const isOutgoing = msg.login === userData.username;
                              const time = new Date(msg.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                              
                              return `
                                <div class="message-bubble ${isOutgoing ? 'message-outgoing' : 'message-incoming'}">
                                  ${msg.message}
                                  <div class="message-time">${time}</div>
                                </div>
                              `;
                            }).join('')
                        }
                      </div>
                      
                      <div class="message-input">
                        <form class="message-form" action="/message" method="post">
                          <input type="hidden" name="recipient" value="${otherUsername}">
                          <input type="text" name="message" placeholder="Type a message..." required autofocus>
                          <button type="submit">Send</button>
                        </form>
                      </div>
                    `
                    : `
                      <div class="empty-state">
                        <svg viewBox="0 0 24 24">
                          <path d="M19.25 3.018H4.75C3.233 3.018 2 4.252 2 5.77v12.495c0 1.518 1.233 2.752 2.75 2.752h14.5c1.517 0 2.75-1.234 2.75-2.752V5.77c0-1.518-1.233-2.752-2.75-2.752zm-14.5 1.5h14.5c.69 0 1.25.56 1.25 1.25v.714l-8.05 5.367c-.273.18-.626.182-.9-.002L3.5 6.482v-.714c0-.69.56-1.25 1.25-1.25zm14.5 14.998H4.75c-.69 0-1.25-.56-1.25-1.25V8.24l7.24 4.83c.383.256.822.384 1.26.384.44 0 .877-.128 1.26-.383l7.24-4.83v10.022c0 .69-.56 1.25-1.25 1.25z"></path>
                        </svg>
                        <h3>Your Messages</h3>
                        <p>Select a conversation or start a new one</p>
                      </div>
                    `
                  }
                </div>
              </div>
              
              <script>
                // Toggle new chat form
                document.getElementById('newChatBtn').addEventListener('click', function(e) {
                  e.preventDefault();
                  const form = document.getElementById('newChatForm');
                  form.classList.toggle('active');
                });
                
                // Auto-scroll to bottom of messages
                const messagesContainer = document.querySelector('.messages');
                if (messagesContainer) {
                  messagesContainer.scrollTop = messagesContainer.scrollHeight;
                }
              </script>
            </body>
          </html>
        `,
        {
          headers: {
            "content-type": "text/html",
            ...getCorsHeaders(),
          },
        },
      );
    }

    // Default route
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>X Messaging App</title>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <style>
                body { 
                  font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
                  max-width: 600px; 
                  margin: 0 auto; 
                  padding: 20px;
                  line-height: 1.5;
                }
                h1 { 
                  color: #1DA1F2; 
                  margin-bottom: 20px;
                }
                .hero {
                  text-align: center;
                  padding: 40px 0;
                }
                .btn { 
                  display: inline-block; 
                  padding: 12px 24px; 
                  background: #1DA1F2; 
                  color: white; 
                  text-decoration: none; 
                  border-radius: 30px;
                  font-weight: bold;
                  margin-top: 20px;
                }
                .features {
                  margin-top: 40px;
                }
                .feature {
                  display: flex;
                  margin-bottom: 20px;
                  align-items: center;
                }
                .feature-icon {
                  width: 50px;
                  height: 50px;
                  background: #e8f5fd;
                  border-radius: 50%;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  margin-right: 20px;
                  color: #1DA1F2;
                  font-size: 24px;
                }
              </style>
            </head>
            <body>
              <div class="hero">
                <h1>X Messaging App</h1>
                <p>A simple and secure way to message other X users privately</p>
                <a href="/login" class="btn">Login with X</a>
              </div>
              
              <div class="features">
                <div class="feature">
                  <div class="feature-icon">🔒</div>
                  <div>
                    <h3>Secure Messaging</h3>
                    <p>Your messages are stored securely in your own private database</p>
                  </div>
                </div>
                
                <div class="feature">
                  <div class="feature-icon">👥</div>
                  <div>
                    <h3>Connect with X Users</h3>
                    <p>Message any X user directly by their username</p>
                  </div>
                </div>
                
                <div class="feature">
                  <div class="feature-icon">💬</div>
                  <div>
                    <h3>Simple Interface</h3>
                    <p>Clean, WhatsApp-like interface for messaging</p>
                  </div>
                </div>
              </div>
            </body>
          </html>
        `,
        {
          headers: {
            "content-type": "text/html",
            ...getCorsHeaders(),
          },
        },
      );
    }

    return new Response("Not found", { status: 404 });
  },
};
