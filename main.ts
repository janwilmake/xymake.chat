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

const IS_LOCALHOST=true;

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
    const username = getCookieValue(cookie, "x_username");
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

    // Initialize DORM client for user database using username
    const client = createClient({
      doNamespace: env.DORM_NAMESPACE,
      version: "v2", // Version prefix for migrations
      migrations,
      ctx, // Pass execution context for waitUntil
      name: dbName || username || "anonymous", // Use username as database name
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

        const securePart = IS_LOCALHOST?"":" Secure;";

      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/;${securePart} SameSite=Lax; Max-Age=600`,
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/;${securePart} SameSite=Lax; Max-Age=600`,
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
          name: String(username), // Use username instead of ID
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
        const securePart = IS_LOCALHOST?"":" Secure;";

        // Set access token cookie and clear temporary cookies
        headers.append(
          "Set-Cookie",
          `x_access_token=${encodeURIComponent(
            access_token,
          )}; HttpOnly; Path=/;${securePart} SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_user_id=${encodeURIComponent(
            id,
          )}; HttpOnly; Path=/;${securePart} SameSite=Lax; Max-Age=34560000`,
        );
        headers.append(
          "Set-Cookie",
          `x_username=${encodeURIComponent(
            username,
          )}; Path=/;${securePart} SameSite=Lax; Max-Age=34560000`,
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
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                  body {
                    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                    background-color: #000;
                    color: #fff;
                    margin: 0;
                    padding: 20px;
                    line-height: 1.5;
                  }
                  h1 {
                    color: #fff;
                  }
                  a {
                    color: #1DA1F2;
                    text-decoration: none;
                  }
                </style>
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
      // Update last_login in the database if we have the username
      if (username) {
        await client.exec(
          "UPDATE users SET last_login = ? WHERE username = ?",
          new Date().toISOString(),
          username
        );
      }

      const headers = new Headers({
        Location: "/",
        ...getCorsHeaders(),
      });

        const securePart = IS_LOCALHOST?"":" Secure;";

      headers.append(
        "Set-Cookie",
        "x_access_token=; Max-Age=0; Path=/; HttpOnly;${securePart} SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_user_id=; Max-Age=0; Path=/; HttpOnly;${securePart} SameSite=Lax",
      );
      headers.append(
        "Set-Cookie",
        "x_username=; Max-Age=0; Path=/;${securePart} SameSite=Lax",
      );

      return new Response("Logging out...", { status: 302, headers });
    }

    // Handle message creation endpoint
    if (url.pathname === "/message" && method === "POST") {
      if (!accessToken || !username) {
        return new Response("Unauthorized", { 
          status: 401, 
          headers: getCorsHeaders() 
        });
      }

      try {
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
        const channelId = createChannelId(username, recipientUsername);
        console.log({channelId,username,recipientUsername,messageText})

        // Add message to current user's database
        await client.exec(
          "INSERT INTO messages (channel_id, login, message) VALUES (?, ?, ?)",
          channelId,
          username,
          messageText
        ).toArray()

        // Create a client for the recipient
        const recipientClient = createClient({
          doNamespace: env.DORM_NAMESPACE,
          version: "v2",
          migrations,
          ctx,
          name: recipientUsername,
        });

        // Add message to recipient's database
        await recipientClient.exec(
          "INSERT INTO messages (channel_id, login, message) VALUES (?, ?, ?)",
          channelId,
          username,
          messageText
        ).toArray()

        // Redirect back to the conversation
        return new Response("Message sent", { 
          status: 302, 
          headers: {
            Location: `/${recipientUsername}`,
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

    // Default route
    if (url.pathname === "/" || url.pathname === "") {
      // If user is logged in, redirect to inbox
      if (accessToken && username) {
        return new Response("Redirecting to inbox...", {
          status: 302,
          headers: {
            Location: "/inbox",
            ...getCorsHeaders(),
          },
        });
      }

      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>X Messaging</title>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <style>
                body { 
                  font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
                  max-width: 600px; 
                  margin: 0 auto; 
                  padding: 20px;
                  line-height: 1.5;
                  background-color: #000;
                  color: #fff;
                }
                h1 { 
                  color: #fff; 
                  margin-bottom: 20px;
                }
                .hero {
                  text-align: center;
                  padding: 40px 0;
                }
                .btn { 
                  display: inline-block; 
                  padding: 12px 24px; 
                  background: #fff; 
                  color: #000; 
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
                  border: 1px solid #333;
                  border-radius: 8px;
                  padding: 15px;
                }
                .feature-icon {
                  width: 50px;
                  height: 50px;
                  background: #333;
                  border-radius: 50%;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  margin-right: 20px;
                  color: #fff;
                  font-size: 24px;
                }
                .x-logo {
                  font-size: 40px;
                  margin-bottom: 20px;
                }
              </style>
            </head>
            <body>
              <div class="hero">
                <div class="x-logo">𝕏</div>
                <h1>X Messaging</h1>
                <p>A secure way to message other X users privately</p>
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
                    <p>Clean, minimal interface for messaging</p>
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

    // Inbox route - show all conversations
    if (url.pathname === "/inbox") {
      if (!accessToken || !username) {
        // Redirect to login if no access token
        return new Response("Redirecting to login...", {
          status: 302,
          headers: {
            Location: "/login",
            ...getCorsHeaders(),
          },
        });
      }

      // Get all messages grouped by channel
      const channels = await client.exec(
        "SELECT DISTINCT channel_id FROM messages"
      ).toArray();

      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>Inbox | X Messaging</title>
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
                  background-color: #000;
                  color: #fff;
                }
                header {
                  background: #000;
                  color: white;
                  padding: 15px 20px;
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                  border-bottom: 1px solid #333;
                }
                .profile {
                  display: flex;
                  align-items: center;
                  gap: 15px;
                }
                .profile img {
                  border-radius: 50%;
                  width: 32px;
                  height: 32px;
                }
                .btn {
                  display: inline-block;
                  padding: 8px 16px;
                  background: #fff;
                  color: #000;
                  text-decoration: none;
                  border-radius: 20px;
                  font-weight: 600;
                  font-size: 14px;
                }
                .container {
                  flex: 1;
                  overflow: auto;
                  padding: 0;
                }
                .channel {
                  padding: 20px;
                  border-bottom: 1px solid #333;
                  display: flex;
                  align-items: center;
                  text-decoration: none;
                  color: #fff;
                }
                .channel:hover {
                  background: #111;
                }
                .channel-avatar {
                  width: 48px;
                  height: 48px;
                  border-radius: 50%;
                  background: #333;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  margin-right: 15px;
                  font-weight: bold;
                  font-size: 20px;
                }
                .channel-details {
                  flex: 1;
                }
                .channel-username {
                  font-weight: bold;
                  margin-bottom: 5px;
                }
                .new-chat {
                  position: fixed;
                  bottom: 20px;
                  right: 20px;
                  width: 60px;
                  height: 60px;
                  border-radius: 50%;
                  background: #fff;
                  color: #000;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  text-decoration: none;
                  font-size: 24px;
                  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }
                .new-chat-modal {
                  display: none;
                  position: fixed;
                  top: 0;
                  left: 0;
                  width: 100%;
                  height: 100%;
                  background: rgba(0,0,0,0.8);
                  z-index: 100;
                  align-items: center;
                  justify-content: center;
                }
                .new-chat-form {
                  background: #000;
                  border: 1px solid #333;
                  border-radius: 12px;
                  padding: 20px;
                  width: 90%;
                  max-width: 400px;
                }
                .new-chat-form h2 {
                  margin-top: 0;
                  margin-bottom: 20px;
                }
                .new-chat-form input, 
                .new-chat-form textarea {
                  width: 100%;
                  padding: 12px;
                  margin-bottom: 15px;
                  border: 1px solid #333;
                  border-radius: 8px;
                  background: #111;
                  color: #fff;
                  font-size: 16px;
                }
                .new-chat-form button {
                  width: 100%;
                  padding: 12px;
                  background: #fff;
                  color: #000;
                  border: none;
                  border-radius: 20px;
                  font-weight: bold;
                  font-size: 16px;
                  cursor: pointer;
                }
                .close-modal {
                  position: absolute;
                  top: 15px;
                  right: 15px;
                  font-size: 24px;
                  color: #fff;
                  background: none;
                  border: none;
                  cursor: pointer;
                }
                .empty-state {
                  display: flex;
                  flex-direction: column;
                  align-items: center;
                  justify-content: center;
                  height: 70vh;
                  text-align: center;
                  padding: 20px;
                  color: #888;
                }
                .x-logo {
                  font-size: 24px;
                  margin-bottom: 10px;
                }
              </style>
            </head>
            <body>
              <header>
                <div class="profile">
                  <div class="x-logo">𝕏</div>
                  <div>Messages</div>
                </div>
                <a href="/logout" class="btn">Logout</a>
              </header>
              
              <div class="container">
                ${channels.length === 0 
                  ? `
                    <div class="empty-state">
                      <div class="x-logo">𝕏</div>
                      <h3>No conversations yet</h3>
                      <p>Start a new conversation by clicking the + button</p>
                    </div>
                  ` 
                  : channels.map(channel => {
                      const channelParts = (channel.channel_id as string).split(':');
                      const otherUser = channelParts[0] === username ? channelParts[1] : channelParts[0];
                      const firstLetter = otherUser.charAt(0).toUpperCase();
                      
                      return `
                        <a href="/${otherUser}" class="channel">
                          <div class="channel-avatar">${firstLetter}</div>
                          <div class="channel-details">
                            <div class="channel-username">@${otherUser}</div>
                            <div class="channel-preview">Tap to view conversation</div>
                          </div>
                        </a>
                      `;
                    }).join('')
                }
              </div>
              
              <a href="#" class="new-chat" id="newChatBtn">+</a>
              
              <div class="new-chat-modal" id="newChatModal">
                <button class="close-modal" id="closeModal">×</button>
                <div class="new-chat-form">
                  <h2>New Message</h2>
                  <form action="/message" method="post">
                    <input type="text" name="recipient" placeholder="Username (without @)" required>
                    <textarea name="message" placeholder="Your message" rows="4" required></textarea>
                    <button type="submit">Send</button>
                  </form>
                </div>
              </div>
              
              <script>
                // Toggle new chat modal
                document.getElementById('newChatBtn').addEventListener('click', function(e) {
                  e.preventDefault();
                  document.getElementById('newChatModal').style.display = 'flex';
                });
                
                document.getElementById('closeModal').addEventListener('click', function() {
                  document.getElementById('newChatModal').style.display = 'none';
                });
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

    // Dynamic user route - /{otherUsername}
    const pathSegments = url.pathname.split('/').filter(Boolean);
    if (pathSegments.length === 1) {
      const otherUsername = pathSegments[0];
      
      if (!accessToken || !username) {
        // Redirect to login if no access token
        return new Response("Redirecting to login...", {
          status: 302,
          headers: {
            Location: "/login",
            ...getCorsHeaders(),
          },
        });
      }

      // Get user data from database
      const userData = await client.exec(
        "SELECT * FROM users WHERE username = ?",
        username
      ).one().catch(() => null);

      if (!userData) {
        return new Response("Redirecting to login...", {
          status: 302,
          headers: { Location: "/login", ...getCorsHeaders() },
        });
      }

      // Create channel ID from the two usernames
      const channelId = createChannelId(username, otherUsername);
      
      // Get messages for this channel
      const messages = await client.exec(
        "SELECT * FROM messages WHERE channel_id = ? ORDER BY created_at ASC",
        channelId
      ).toArray();

      return new Response(
        html`
          <!DOCTYPE html>
          <html>
            <head>
              <title>@${otherUsername} | X Messaging</title>
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
                  background-color: #000;
                  color: #fff;
                }
                header {
                  background: #000;
                  color: white;
                  padding: 15px 20px;
                  display: flex;
                  align-items: center;
                  border-bottom: 1px solid #333;
                }
                .back-button {
                  margin-right: 15px;
                  text-decoration: none;
                  color: #fff;
                  font-size: 20px;
                }
                .user-info {
                  flex: 1;
                  font-weight: bold;
                }
                .messages-container {
                  flex: 1;
                  overflow-y: auto;
                  padding: 20px;
                }
                .message {
                  max-width: 80%;
                  padding: 12px 16px;
                  margin-bottom: 10px;
                  border-radius: 18px;
                  position: relative;
                }
                .message-outgoing {
                  background: #333;
                  color: #fff;
                  margin-left: auto;
                  border-bottom-right-radius: 4px;
                }
                .message-incoming {
                  background: #222;
                  color: #fff;
                  margin-right: auto;
                  border-bottom-left-radius: 4px;
                }
                .message-time {
                  font-size: 0.7em;
                  margin-top: 5px;
                  opacity: 0.7;
                }
                .message-input {
                  padding: 15px;
                  border-top: 1px solid #333;
                }
                .message-form {
                  display: flex;
                  gap: 10px;
                }
                .message-form input {
                  flex: 1;
                  padding: 14px;
                  border: 1px solid #333;
                  border-radius: 24px;
                  background: #111;
                  color: #fff;
                  font-size: 16px;
                }
                .message-form button {
                  background: #fff;
                  color: #000;
                  border: none;
                  border-radius: 50%;
                  width: 46px;
                  height: 46px;
                  font-size: 20px;
                  cursor: pointer;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                }
                .empty-state {
                  display: flex;
                  flex-direction: column;
                  align-items: center;
                  justify-content: center;
                  height: 100%;
                  text-align: center;
                  padding: 20px;
                  color: #888;
                }
              </style>
            </head>
            <body>
              <header>
                <a href="/inbox" class="back-button">←</a>
                <div class="user-info">@${otherUsername}</div>
              </header>
              
              <div class="messages-container" id="messagesContainer">
                ${messages.length === 0 
                  ? `
                    <div class="empty-state">
                      <p>No messages yet</p>
                      <p>Send a message to start the conversation</p>
                    </div>
                  ` 
                  : messages.map(msg => {
                      const isOutgoing = msg.login === username;
                      const time = new Date(msg.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                      
                      return `
                        <div class="message ${isOutgoing ? 'message-outgoing' : 'message-incoming'}">
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
                  <input type="text" name="message" placeholder="Message" required autofocus>
                  <button type="submit">→</button>
                </form>
              </div>
              
              <script>
                // Auto-scroll to bottom of messages
                const messagesContainer = document.getElementById('messagesContainer');
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
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

    return new Response("Not found", { 
      status: 404,
      headers: getCorsHeaders()
    });
  },
};
