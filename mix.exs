defmodule Erljwt.Mixfile do
  use Mix.Project

  def project do
    [app: :erljwt,
     version: "0.1.0",
     language: :erlang,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    []
  end

  defp deps do
    [{:decimal, "~> 0.2.0",
      :ex_doc, github: "elixir-lang/ex_doc"}]
  end

  defp description do
    """
    A simple JSON webtoken encoding/decoding library without C dependencies and supporting maps.
    """
  end

  defp package do
    [# These are the default files included in the package
     name: :erljwt,
     files: ["src", "test", "mix.exs", "README*", "readme*", "LICENSE*", "license*"],
     maintainers: ["Bas Wegh"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "https://github.com/indigo-dc/erljwt"}
     ]
  end
end