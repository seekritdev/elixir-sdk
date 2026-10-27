# seekrit — Elixir SDK

Read-path SDK for [seekrit](https://seekrit.dev). Authenticate with a service
token, resolve your environment, and get **decrypted** secrets — the API only
ever returns ciphertext; decryption happens in your process.

> This repo is a **read-only mirror** published from seekrit's monorepo so the
> code that holds your token and decrypts plaintext is auditable. Don't commit
> here — it's overwritten on each sync. Issues and PRs welcome.

## Install

```elixir
# mix.exs
def deps do
  [{:seekrit, "~> 0.1"}]
end
```

Requires Elixir 1.18+ / OTP 25+. **No dependencies** — `:crypto` and
`:public_key` for the decrypt path, `:httpc` for the request, and the `JSON`
module Elixir 1.18 ships.

## Usage

```elixir
secrets = Seekrit.resolve!()        # token from $SEEKRIT_TOKEN
secrets["DATABASE_URL"]             # "postgres://…"
```

Or hold a client, which parses the token once:

```elixir
{:ok, client} = Seekrit.Client.new()
{:ok, secrets} = Seekrit.Client.resolve(client)

Seekrit.Client.get!(client, "API_KEY", "")
```

Every function has a `{:ok, _} | {:error, exception}` form and a `!` form that
raises.

### Releases and `config/runtime.exs`

`config/runtime.exs` runs before your applications start, which is the right
place to pull secrets in. `Seekrit.load_env!/1` starts `:inets` and `:ssl`
itself, so it works there:

```elixir
# config/runtime.exs
if config_env() == :prod do
  Seekrit.load_env!()

  config :my_app, MyApp.Repo, url: System.fetch_env!("DATABASE_URL")
  config :my_app, MyAppWeb.Endpoint, secret_key_base: System.fetch_env!("SECRET_KEY_BASE")
end
```

`load_env!/1` keeps variables that are already set; pass `override: true` to let
seekrit win.

### Configuration

| Option | Env var | Default |
| --- | --- | --- |
| `:token` | `SEEKRIT_TOKEN` | — (required) |
| `:api_url` | `SEEKRIT_API_URL` | `https://api.seekrit.dev` |
| `:with` | — | `%{}` |
| `:connect_timeout` / `:timeout` | — | `10_000` / `30_000` (milliseconds) |
| `:interpolate` | — | `true` |
| `:ssl_options` | — | verify against the system trust store |

A service token binds to a single app environment (plus its composed group
slices). Pass `:with` to pull a different environment slice of a composed group:

```elixir
Seekrit.resolve!(with: %{"shared" => "dev"})
```

### Errors

Elixir exceptions have no hierarchy, so there are four types rather than one
tree:

- `Seekrit.ApiError` — non-2xx from the API; has `:status` and `:code`
  (`"unauthorized"`, `"forbidden"`, `"not_found"`, …).
- `Seekrit.CryptoError` — a token or ciphertext could not be parsed/decrypted.
- `Seekrit.ReferenceError` — a `${…}` reference cycle, with `:code`.
- `Seekrit.Error` — configuration and transport failures.

`resolve` is **fail-closed**: any resolve or decrypt failure is an error rather
than a partial result. A `Seekrit.Client` and a `Seekrit.Crypto.TokenKey` both
redact themselves in `inspect/1`, so a crash report cannot leak the credential.

## Secret references

A secret's value may reference another with `${OTHER_SECRET}`. References are
stored literally and expanded here, after the layers are merged — so a reference
picks up whichever layer won that name, and rotating the referenced secret
updates every value that uses it. `$${OTHER_SECRET}` is a literal; an unknown
name is left as written; a reference cycle is an error. Full rules:
[seekrit.dev/docs/guides/references](https://seekrit.dev/docs/guides/references).

```elixir
Seekrit.resolve!(interpolate: false)   # get the stored text instead
```

## Zero-knowledge

`GET /v1/resolve` returns ciphertext plus a data-encryption key wrapped to your
token's public key. This SDK recovers the token's private key, unwraps the DEK
(ECDH P-256 → HKDF-SHA256 → AES-256-GCM), and decrypts each secret
(AES-256-GCM, AAD-bound to `environmentId/NAME`) — the exact scheme used by the
CLI, `seekrit run`, and every other seekrit client. See
[seekrit.dev/docs](https://seekrit.dev/docs/concepts/encryption).

The request pins `verify: :verify_peer` against the system trust store;
`:httpc` does not verify certificates unless told to, and an unverified
connection would be a silent downgrade of the whole token-bearing request.

## Tests

```sh
mix test
```

`test/vectors_test.exs` decrypts a golden fixture generated from the canonical
`@seekrit/crypto` implementation and asserts byte-for-byte equality, so this SDK
cannot drift from the others.

## License

MIT

## Service token v2

Keep one `SEEKRIT_TOKEN`: `skt_<id>_v2.<auth-secret>.<private-key>`.
The client sends only `skt_<id>_v2.<auth-secret>` to the API and uses the private
key locally to decrypt. Legacy tokens are rejected before any API request;
upgrade clients and replace legacy tokens through the dashboard. A stolen
HTTP credential cannot decrypt environment payloads, but stealing the full
local bundle still exposes the private key. Treat the full bundle as a secret.
