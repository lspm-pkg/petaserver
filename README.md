# Peta Server
> Unlimited Discord Storage (up to 1.7PB**) as a API Endpoint

---

## How does it work

It uses discord and some HTTP stuff to make an API server which then a client like [ours](https://github.com/lspm-pkg/petaclient) will connect to.

---

## How much is the size

Technically unlimited but your your mileage may vary.

---

## What are the catches

1. Discord can ban you.
2. Discord can rate limit your bot.
3. Reads are very slow depending on what you're doing (there is adaptive read ahead and if the write is pending, it could be in the cache)
   - writes are very fast due to server side caching.
4. Without a client application, it is not easy to use.

---

## How do I use it

Please proceed at your own risk, and read UsageGuide.md in this repo.

It also includes a client usage guide, but API guide is not added yet.
