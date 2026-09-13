defmodule Seekrit.Error do
  @moduledoc """
  Configuration and transport failures: a missing or empty service token, a
  network error, an unparseable response body.

  Elixir exceptions have no hierarchy, so this is not a superclass of the other
  three — see `Seekrit` for the full list to rescue.
  """
  defexception [:message]

  @type t :: %__MODULE__{message: String.t()}
end

defmodule Seekrit.CryptoError do
  @moduledoc """
  A token, wrapped DEK, or secret ciphertext could not be parsed or decrypted.

  Deliberately unspecific: a decrypt failure does not distinguish "wrong key"
  from "tampered data" from "mismatched context".
  """
  defexception [:message]

  @type t :: %__MODULE__{message: String.t()}
end

defmodule Seekrit.ReferenceError do
  @moduledoc """
  A `${OTHER_SECRET}` reference could not be expanded: a cycle, or an expansion
  that grows without bound.

  An *unknown* reference is not an error — it is left as literal text, and
  reported in `Seekrit.Interpolate.Result`'s `:unresolved`.
  """
  defexception [:message, :code]

  @type code :: :cycle | :too_large
  @type t :: %__MODULE__{message: String.t(), code: code()}
end

defmodule Seekrit.ApiError do
  @moduledoc """
  The resolve API returned a non-2xx response.

  `:status` is the HTTP status; `:code` is `error.code` from the API body
  (`"unauthorized"`, `"forbidden"`, `"not_found"`, …), or `"internal"` when the
  body did not parse as an API error.
  """
  defexception [:status, :code, :detail]

  @type t :: %__MODULE__{status: pos_integer(), code: String.t(), detail: String.t()}

  @impl true
  def message(%__MODULE__{status: status, code: code, detail: detail}) do
    "#{status} #{code}: #{detail}"
  end
end
