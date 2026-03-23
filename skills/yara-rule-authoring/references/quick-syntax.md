# Quick Syntax

## Minimal Skeleton

```yara
rule example_rule
{
  meta:
    author = "Codex"
    description = "Brief purpose"

  strings:
    $s1 = "literal text" ascii wide

  condition:
    $s1
}
```

## Useful Patterns

### Multiple strings

```yara
condition:
  any of them
```

### Threshold match

```yara
condition:
  2 of ($api*)
```

### PE-aware rule

```yara
import "pe"

rule suspicious_pe_example
{
  strings:
    $s1 = "CreateRemoteThread" ascii
    $s2 = "VirtualAllocEx" ascii

  condition:
    uint16(0) == 0x5A4D and pe.is_32bit() and all of ($s*)
}
```

## Validation Checklist

- Every referenced string identifier exists.
- Imported modules are actually used.
- The condition is specific enough to avoid obvious false positives.
- The rule text is complete and can be saved directly to a `.yar` file.
