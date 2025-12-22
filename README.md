# Peta Server
> Unlimited Discord Storage (up to 1.7PB**) as a API Endpoint

---

## How does it work

Petaserver uses Discord(.py) and FastAPI to make an API server which then a client like [petaclient](https://github.com/lspm-pkg/petaclient) can connect to.

---

## How much can it store

The amount of storage is technically unlimited but your mileage may vary.

---

## What are the catches

1. Discord can ban you.
2. Discord can rate limit your bot.
3. Reads are very slow depending on what you're doing (There is adaptive read ahead for heavy tasks and extensive caching)
   - writes are very fast due to server side caching.
4. Without a client application, it is not particularly easy to use.

---

## How do I use it

Please proceed at your own risk, and read [UsageGuide.md](https://github.com/lspm-pkg/petaserver/blob/main/UsageGuide.md) in this repo.

It also includes a client usage guide, but API guide is not added yet.
