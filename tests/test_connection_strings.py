"""clowk's own two connection-string rules, and why both capture the WHOLE string.

A credential in a connection string is never the only sensitive thing in it. The hostname, the
username, the database name and the account name are internal topology the model does not need, and
replacing only the password leaves every one of them in the prompt -- while a single $NAME is also
how the value is actually consumed: `psql "$(clowk get DATABASE_URL)"`.

`scheme://user:pass@host/db` has been treated that way since the rule was written.
`key=value;key=value;` had not: an Azure storage string had its account key replaced and kept
`AccountName=prodstore;EndpointSuffix=core.windows.net`, which named the account to the model just
as plainly as the key would have.

Fixtures are synthetic and assembled from adjacent literals so the credential-bearing key never
appears contiguously in this file -- Azure storage and Service Bus keys are GitHub push-protection
partner patterns. See NOTES.md.
"""
import unittest

from clowk.detect import KV_ID, URI_ID, scan

# 64 and 32 synthetic bytes, base64'd: the real lengths for a storage key and a SAS key.
STORAGE_KEY = ("Zk9tQjNyTHc4dVhhSDJwVjZuRDRzWTdjRWc1aktmUW1UeUJ4"
               "TjFvUmw0dldoQzhkR3oyU3BLNGVBaVU5bXJYdA==")
SAS_KEY = "cVc4bkoyeEZ0UjdtQTVoTDNkWXBLNnNHOXZCMXo0VQ="
COSMOS_KEY = ("TXA3d0oyeEZ0UjdtQTVoTDNkWXBLNnNHOXZCMXo0VXFhWmc4"
              "ZExtNXlUcjNCbkgyVjZjRjRrUzdKd1g5ZUEwdA==")
SIGNALR_KEY = "aFo0bVQ5cVc3eEwyRHZOOGtSNXNHM2JZcEE2Y0UxdUo="
SQL_PASSWORD = "Tr0ub4dor&3xKq7Zm"

AZURE_STORAGE = ("DefaultEndpointsProtocol=https;AccountName=prodstore;"
                 + "Account" "Key=" + STORAGE_KEY + ";EndpointSuffix=core.windows.net")
SERVICE_BUS = ("Endpoint=sb://acme-prod.servicebus.windows.net/;"
               "SharedAccessKeyName=RootManageSharedAccessKey;"
               + "SharedAccess" "Key=" + SAS_KEY + ";EntityPath=orders")
SQL_SERVER = ("Server=tcp:acme-prod.database.windows.net,1433;Initial Catalog=orders;"
              "User ID=svc_app;" + "Pass" "word=" + SQL_PASSWORD + ";Encrypt=True")
MYSQL = "Server=db1.internal;Database=orders;Uid=svc_app;" + "Pw" "d=" + SQL_PASSWORD + ";"
COSMOS = ("AccountEndpoint=https://acme.documents.azure.com:443/;"
          + "Account" "Key=" + COSMOS_KEY + ";")
SIGNALR = ("Endpoint=https://acme.service.signalr.net;"
           + "Access" "Key=" + SIGNALR_KEY + ";Version=1.0;")


def widest(text, needle):
    """The longest finding covering `needle` -- the one hook_prompt.capture() replaces first."""
    covering = sorted((f for f in scan(text) if needle in f.secret), key=lambda f: len(f.secret))
    return covering[-1] if covering else None


class TestTheWholeConnectionStringIsCaptured(unittest.TestCase):
    """Each of these is a real product's documented connection-string format."""

    CASES = [
        ("azure storage", AZURE_STORAGE, STORAGE_KEY, "AZURE_STORAGE_CONNECTION_STRING"),
        ("service bus", SERVICE_BUS, SAS_KEY, "SERVICE_BUS_CONNECTION_STRING"),
        ("sql server", SQL_SERVER, SQL_PASSWORD, "DATABASE_CONNECTION_STRING"),
        ("mysql", MYSQL, SQL_PASSWORD, "DATABASE_CONNECTION_STRING"),
        ("cosmos db", COSMOS, COSMOS_KEY, "COSMOS_CONNECTION_STRING"),
        ("signalr", SIGNALR, SIGNALR_KEY, "SIGNALR_CONNECTION_STRING"),
    ]

    def test_the_whole_string_is_the_finding_not_just_the_credential(self):
        for label, conn, credential, _ in self.CASES:
            finding = widest("please debug this: " + conn + " -- it times out", credential)
            self.assertIsNotNone(finding, "%s: nothing covered the credential" % label)
            self.assertEqual(finding.secret, conn.rstrip(";"), label)
            self.assertEqual(finding.rule_id, KV_ID, label)

    def test_the_env_name_is_one_a_human_would_actually_use(self):
        for label, conn, credential, env in self.CASES:
            self.assertEqual(widest(conn, credential).env, env, label)

    def test_it_is_high_confidence_like_the_uri_rule(self):
        # A credential-bearing key in a `key=value;` string is not a shape that happens to look
        # like a credential, it is definitionally one -- same reasoning as the URI rule.
        for label, conn, credential, _ in self.CASES:
            self.assertEqual(widest(conn, credential).confidence, "high", label)

    def test_no_internal_topology_survives_the_rewrite(self):
        # What capture() does: replace the longest finding first. The point of the whole-string
        # capture is that the account, host, user and database names go with the credential.
        for label, conn, credential, env in self.CASES:
            finding = widest("look at " + conn, credential)
            rewritten = ("look at " + conn).replace(finding.secret, "$" + env)
            for leak in ("prodstore", "acme-prod", "acme.documents", "acme.service",
                         "svc_app", "db1.internal", "orders"):
                self.assertNotIn(leak, rewritten, "%s leaked %r" % (label, leak))

    def test_the_span_matches_the_secret_it_reports(self):
        # hook_prompt rewrites by string replacement, but vault metadata and every future
        # span-based consumer read start/end. A span that does not frame the secret is a bug.
        text = "connection string: " + AZURE_STORAGE + " (staging)"
        finding = widest(text, STORAGE_KEY)
        self.assertEqual(text[finding.start:finding.end], finding.secret)


class TestPlaceholdersAreNotCredentials(unittest.TestCase):
    """Documentation, .env.example and half-written snippets all look like this."""

    NOT_CREDENTIALS = [
        ("angle brackets", "DefaultEndpointsProtocol=https;AccountName=x;"
                           + "Account" "Key=<your-account-key>;EndpointSuffix=core.windows.net"),
        ("named placeholder", "Server=db;Database=orders;Uid=root;" + "Pass" "word=changeme;"),
        ("the word itself", "Server=db;Database=orders;Uid=root;" + "Pass" "word=password;"),
        ("shell reference", "Server=db;Database=orders;Uid=root;" + "Pass" "word=$DB_PASS;"),
        ("windows reference", "Server=db;Database=orders;Uid=root;" + "Pass" "word=%DB_PASS%;"),
        ("empty value", "Server=db;Database=orders;Uid=root;" + "Pass" "word=;Encrypt=True"),
        ("brace template", "Server=db;Database=orders;Uid=root;" + "Pass" "word={{password}};"),
        ("redacted", "DefaultEndpointsProtocol=https;AccountName=x;"
                     + "Account" "Key=***REDACTED***;EndpointSuffix=core.windows.net"),
        ("xxxx", "Server=db;Database=orders;Uid=root;" + "Pass" "word=xxxxxxxx;"),
    ]

    def test_a_placeholder_value_is_not_filed(self):
        for label, text in self.NOT_CREDENTIALS:
            hits = [f.rule_id for f in scan(text) if f.rule_id == KV_ID]
            self.assertEqual(hits, [], "%s was filed as a connection string" % label)


class TestOrdinarySemicolonTextIsNotAConnectionString(unittest.TestCase):
    """`key=value;` is also CSS, a shell line, a query string and a JDBC-shaped sentence."""

    CLEAN = [
        ("css", 'style="color=red;font-size=12px;margin=0"'),
        ("shell env", "run PGPASSWORD=localdev psql -h db1 -U postgres orders"),
        ("shell chain", "cd /srv/app; make build; make test; echo done"),
        ("query string", "GET /v1/items?limit=50&offset=100&sort=created_at HTTP/1.1"),
        ("prose", "the password field and the key field both need a semicolon; fix the parser"),
        ("makefile", "CFLAGS=-O2 -Wall; LDFLAGS=-lm; PREFIX=/usr/local"),
        ("ini", "[core]\nrepositoryformatversion=0\nfilemode=true\nbare=false"),
        ("no credential key", "Server=db1.internal;Database=orders;Uid=svc_app;Encrypt=True;"),
    ]

    def test_none_of_these_is_reported_as_a_connection_string(self):
        for label, text in self.CLEAN:
            hits = [(f.rule_id, f.secret) for f in scan(text) if f.rule_id == KV_ID]
            self.assertEqual(hits, [], "%s was read as a connection string: %s" % (label, hits))

    def test_a_lone_credential_pair_is_not_a_connection_string(self):
        """One pair names no topology, so there is nothing to hide beyond the value itself.

        Two pairs is therefore the rule's floor, and it is what makes the whole-string capture
        meaningful rather than a second spelling of the vendored keyword rules.

        Measured while writing this, and left alone deliberately: those keyword rules capture
        `[\\w.=-]{10,150}`, so `Password=Tr0ub4dor&3xKq7Zm` standing alone is caught by NOTHING --
        the ampersand truncates the value to nine characters, under generic-api-key's minimum of
        ten. Inside a connection string this rule now catches it whole, which is a recall gain
        this rule was not written for. A lone pair with a punctuated value is a gap in the
        vendored charset, not in this rule, and closing it belongs to the ruleset.
        """
        lone = "Pass" "word=" + SQL_PASSWORD + ";"
        self.assertEqual([f for f in scan(lone) if f.rule_id == KV_ID], [])
        alphanumeric = "Pass" "word=aB3xQ9zLmN4pR7tV2wY8;"
        self.assertTrue(scan(alphanumeric), "a lone pair must still reach the vendored rules")
        self.assertEqual([f for f in scan(alphanumeric) if f.rule_id == KV_ID], [])


class TestTheUriSiblingStillBehaves(unittest.TestCase):
    """The rule this one was modelled on. Its whole-URI capture is the precedent being extended."""

    def test_a_postgres_url_is_filed_whole_under_database_url(self):
        finding = widest("psql postgresql://svc_app:s3cr3tP4ss@db1.internal:5432/orders now",
                         "s3cr3tP4ss")
        self.assertEqual(finding.rule_id, URI_ID)
        self.assertEqual(finding.env, "DATABASE_URL")
        self.assertEqual(finding.secret, "postgresql://svc_app:s3cr3tP4ss@db1.internal:5432/orders")

    def test_a_placeholder_password_in_a_uri_is_still_skipped(self):
        self.assertEqual([f for f in scan("postgresql://postgres:changeme@localhost:5432/dev")
                          if f.rule_id == URI_ID], [])


if __name__ == "__main__":
    unittest.main()
