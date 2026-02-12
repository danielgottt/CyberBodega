# CyberBodega Tagging Guide

This document provides guidelines for adding tags to resources in the CyberBodega repository.

## Tag Types

### ![Open Source](https://img.shields.io/badge/-Open%20Source-green)
Use for:
- GitHub repositories with open-source licenses
- Tools with publicly available source code
- Community-driven projects

### ![Free](https://img.shields.io/badge/-Free-blue)  
Use for:
- Completely free resources (no payment required)
- Free websites and services
- Free training materials
- May require registration but no payment

### ![Freemium](https://img.shields.io/badge/-Freemium-yellow)
Use for:
- Services with free tier + paid upgrades
- Tools with limited free version
- Platforms with trial periods

### ![Paid](https://img.shields.io/badge/-Paid-red)
Use for:
- Commercial/licensed software
- Paid-only services
- Subscription-based platforms

## How to Add Tags

Simply add the badge markdown before the link:

```markdown
- ![Open Source](https://img.shields.io/badge/-Open%20Source-green) [Tool Name](url) Description
```

## Priority Areas to Tag

1. **Training Resources** - Users want to know what's free
2. **Blue Team Tools** - Helps with budget planning
3. **Red Team Tools** - Important for legal/licensing
4. **Cloud Tools** - Often have complex pricing
5. **Malware Analysis Tools** - Many are freemium

## Examples

```markdown
### Training
- ![Free](https://img.shields.io/badge/-Free-blue) [TryHackMe Free Labs](url) Description
- ![Freemium](https://img.shields.io/badge/-Freemium-yellow) [TryHackMe Premium](url) Description

### Tools
- ![Open Source](https://img.shields.io/badge/-Open%20Source-green) [Velociraptor](url) Description
- ![Paid](https://img.shields.io/badge/-Paid-red) [Cobalt Strike](url) Description
```

## Notes

- Don't tag everything - focus on tools/platforms where cost matters
- News sites and blogs generally don't need tags
- Articles and write-ups don't need tags
- GitHub repos are usually tagged as Open Source
