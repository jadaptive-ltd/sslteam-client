# SSLTeam Java Client

Typed, framework-neutral Java access to SSLTeam certificate and authentication services.

`sslteam-client` is the service-facing client used by the SSLTeam CLI and available to other Java
applications. It handles the repetitive protocol work around the SSLTeam API while leaving
application policy, credential storage, and TLS trust decisions with the caller.

**Current version:** `1.0.0-SNAPSHOT`<br>
**Java:** 25

## What it provides

`SslTeamClient` exposes typed operations for:

- authentication refresh, device authorization, password changes, and server ping
- application root CA setup, completion, status, download, retirement, and revocation
- intermediate CA requests, signing imports, current material, history, retirement, and revocation
- leaf certificate generation, listing, certificate or chain downloads, and revocation
- CA inventory and certificate revocation audit queries

The client also provides the protocol behavior around those operations:

- JSON serialization and deserialization through Jackson
- endpoint construction and URL encoding
- correlation IDs for request tracing
- bounded request timeouts
- HTTP response validation
- retry classification for transient I/O failures

## Using the client

The client accepts a transport so an application can choose its own network and trust policy. The
transport is supplied once, while the server origin and access token are passed to each operation:

```java
import java.net.http.HttpClient;
import com.jadaptive.sslteam.client.SslTeamClient;
import com.jadaptive.sslteam.client.SslTeamHttpTransport;
import com.jadaptive.sslteam.client.PingResponse;

HttpClient httpClient = HttpClient.newHttpClient();
SslTeamHttpTransport transport = httpClient::send;
SslTeamClient client = new SslTeamClient(transport);

PingResponse ping = client.ping("https://sslteam.example.com", accessToken);
```

`SslTeamHttpTransport` is a small interface around sending a prepared JDK `HttpRequest`. The
example adapts the standard JDK `HttpClient` with a method reference. For origin-scoped TLS
profiles, use the built-in `SslTeamTlsTransport` shown below. A fake implementation can also be
supplied for unit tests.

For the standard origin-scoped TLS transport, provide a caller-owned profile store. This keeps
origin selection and trust material under the application's control:

```java
import com.jadaptive.sslteam.client.SslTeamClient;
import com.jadaptive.sslteam.client.SslTeamTlsTransport;

SslTeamClient client = new SslTeamClient(new SslTeamTlsTransport(profileStore));
```

The `profileStore` implementation belongs to the embedding application. The library does not
assume a filesystem, database, environment-variable layout, or CLI configuration format.

### Authenticated certificate operations

A typical request sequence is to authenticate once, retain the returned access token in the
application's secure session handling, and use that token for scoped certificate operations:

```java
import com.jadaptive.sslteam.cert.api.contract.intermediate.IntermediateCurrentResponse;
import com.jadaptive.sslteam.cert.api.contract.root.RootCertificateResponse;
import com.jadaptive.sslteam.client.AuthTokenResponse;
import com.jadaptive.sslteam.client.SslTeamClient;

String baseUrl = "https://sslteam.example.com";
String teamCode = "default";
String environment = "default";

AuthTokenResponse tokens = client.login(baseUrl, username, password);
String accessToken = tokens.accessToken();

client.ping(baseUrl, accessToken);
RootCertificateResponse root = client.applicationRoot(
  baseUrl, accessToken, teamCode, environment);
IntermediateCurrentResponse intermediate = client.currentIntermediate(
  baseUrl, accessToken, teamCode, environment);
```

The `teamCode` and `environment` values are part of the server scope. The server remains
authoritative for whether the authenticated caller may access that scope and perform the requested
certificate operation.

The complete server-facing sequence is available in
[`SslTeamClientIntegrationTest`](https://github.com/jadaptive-ltd/sslteam-client/blob/main/src/test/java/com/jadaptive/sslteam/client/SslTeamClientIntegrationTest.java).

## How it fits into SSLTeam

The client depends on [`sslteam-api`](https://github.com/jadaptive-ltd/sslteam-api) for the shared
request, response, scope, inventory, and lifecycle types. In `sslteam-services`, the CLI supplies
the TLS transport and connection/profile persistence, while the server remains authoritative for
authorization, team and environment scope, certificate policy, lifecycle transitions, and audit
history.

This separation makes the client suitable for:

- Java command-line tools
- backend services and automation workers
- certificate-management integrations
- tests and adapters that need typed SSLTeam API access

## Maven coordinates

```xml
<dependency>
  <groupId>com.jadaptive</groupId>
  <artifactId>sslteam-client</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

The current version is a development snapshot. Snapshot consumers should use the repository that
hosts the snapshot and resolve the matching `sslteam-api` version transitively:

```xml
<repository>
  <id>central-jadaptive</id>
  <url>https://central.sonatype.com/repository/maven-snapshots/</url>
  <releases><enabled>false</enabled></releases>
  <snapshots><enabled>true</enabled></snapshots>
</repository>
```

## Related projects

- [`sslteam-api`](https://github.com/jadaptive-ltd/sslteam-api): shared Java API contracts
- [SSLTeam organization](https://github.com/jadaptive-ltd): project source and issue tracking

## License

Copyright (C) 2026 Jadaptive Limited.

This project is licensed under the Apache License, Version 2.0. See the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for details.