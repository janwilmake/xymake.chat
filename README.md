An infinitely scalable X Chat using Durable Objects.

It's super basic but it's cool DO because it's literally scalable to all of X and it's just 1100 lines of code.

[![janwilmake/xymake.chat context](https://badge.forgithub.com/janwilmake/xymake.chat?lines=false)](https://uithub.com/janwilmake/xymake.chat?lines=false)

How I made it:

- Made possible by the [DORM Template](https://github.com/janwilmake/dorm) and [X OAuth Template](https://uuithub.com/janwilmake/x-oauth-template)
- [![](https://b.lmpify.com/Iteration_1)](https://lmpify.com/httpsuuithubcom-m69t8m0)
- [![](https://b.lmpify.com/Iteration_2)](https://lmpify.com/httpsuithubcomj-ea8mux0)
- After that, I just needed a small fix: Claude forgot to put `.toArray()` behind the query to insert the messages which caused it to fail

Try it here: https://chat.xymake.com

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/janwilmake/worker-tailproxy/tree/main) <!-- for easy deployment, ensure to add this into the readme of the created project -->

Potential ways to improve things:

- add websocket or poll reloading
- add unread count
- add last message column and ensure contains `{username}: {message}` (use new migration)

[![](https://b.lmpify.com/Improve_It!)](https://lmpify.com/httpsuithubcomj-qql14p0)

Could this become a real thing? [let's discuss](https://x.com/janwilmake/status/1926366057482109066)