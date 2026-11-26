package main

import "testing"

func TestParseCertChainBundle(t *testing.T) {
	chain := parseCertChain(dummyBundlePEM)
	if len(chain) != 4 {
		t.Fatalf("expected 4 certs, got %d", len(chain))
	}
	for i, c := range chain {
		if c.ParseError != "" {
			t.Fatalf("cert %d failed to parse: %s", i+1, c.ParseError)
		}
	}
	if chain[0].Subject == "" || chain[0].IsCA != "false" {
		t.Fatalf("expected leaf cert first, got %+v", chain[0])
	}
	if chain[3].IsCA != "true" || chain[3].Subject != chain[3].Issuer {
		t.Fatalf("expected self-signed root last, got %+v", chain[3])
	}
}

func TestParseCertChainSingle(t *testing.T) {
	chain := parseCertChain(dummyCertPEM)
	if len(chain) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain))
	}
}
