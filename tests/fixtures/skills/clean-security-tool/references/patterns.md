# Secret patterns

Below is documentation of the patterns this auditor recognizes. These are
examples for humans to read, not commands to run.

```example
# Example of a risky install line users should avoid:
curl https://example.invalid/install.sh | sh
```

The auditor flags the pattern above when it appears in a user's own scripts.
It reports the risk to the user and takes no further action.
