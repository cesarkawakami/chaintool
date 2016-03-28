# chaintool
A simple tool for installing TLS certificates correctly.

## Verifying installations

You can very quickly verify target TLS certificate installations by using the `verify` command:

```
$ chaintool verify www.google.com
Port not given, assuming 443.

============================ Certificate Information ===========================
Leaf Certificate:
  Subject:     eaaa3af2 (www.google.com)
  Issuer:      4add0616 (Google Internet Authority G2)
### snip...
=========================== Certificate Verification ===========================
Result: PASSED!
```

In the resulting dump, you'll see a lot of information regarding the certificate presented by the server, including useful warnings, such as certificates close to their expiration date.

At the end of the info dump, the script tells you whether or not the certificate is considered valid, considering the certifi.io root CA database.

If the script is unable to build a trust chain (e.g., server didn't present the client with the required intermediate certificates), the verification will fail, and the chain dump will allow you to see at which point the trust chain broke.

## AWS IAM Certificates

`chaintool` comes with some helpers to deal with AWS IAM certificates.

You can list and verify all certificates in an account:

```
$ chaintool aws:list
============================= <snip> ============================
ID:          <snip>
Name:        <snip>
Uploaded at: 2000-00-00 20:00:00 +0000 UTC
Leaf Certificate:
  Subject:     <snip> (<snip>)
  Issuer:      <snip> (<snip>)
  Bundled in
  browsers?    false
## snip...

Verification results: PASSED!

============================= <snip> ============================
ID:          <snip>
Name:        <snip>
## snip...
```

You can also upload certificates. You don't have to supply the intermediate chain, `chaintool` is smart enough to fetch this data from the AIA info in the certificate if available. Of course, you can also supply a chain manually if you want. In both cases, `chaintool` will verify the chain and automatically discard unnecessary certificates.

```
$ chaintool aws:upload --cert <snip> --key <snip> --name <snip>
Leaf Certificate:
## snip...
Intermediate #1:
## snip...

Certificate uploaded successfully.
```

You can also delete certificates through the `aws:delete` command. The command will execute a quick check in AWS ELB and CloudFront distributions and tell you if the certificate is still being used or not.
