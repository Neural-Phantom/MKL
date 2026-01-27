```text
███╗   ███╗ ██████╗ ██████╗ ███████╗██████╗ ███╗   ██╗    ██╗  ██╗██╗██╗     ██╗     
████╗ ████║██╔═══██╗██╔══██╗██╔════╝██╔══██╗████╗  ██║    ██║ ██╔╝██║██║     ██║     
██╔████╔██║██║   ██║██║  ██║█████╗  ██████╔╝██╔██╗ ██║    █████╔╝ ██║██║     ██║     
██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  ██╔══██╗██║╚██╗██║    ██╔═██╗ ██║██║     ██║     
██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗██║  ██║██║ ╚████║    ██║  ██╗██║███████╗███████╗
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
                                                                                     
                  [ v8.0 GOLD MASTER // AUTOMATED OFFENSIVE INFRASTRUCTURE ]

           .                                                      .
             .n                   .                 .                  n.
       .   .dP                  dP                   9b                 9b.    .
      4    qXb         .       dX                     Xb       .        dXp     t
     dX.    9Xb      .dXb    __                     __    dXb.     dXP     .Xb
     9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
      9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
       `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
         `9XXXXXXXXXXXP' `9XX'   RED   `98v8P'   TEAM  `XXP' `9XXXXXXXXXXXP'
             ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                             )b.  .dbo.dP'`v'`9b.odb.  .dX(
                           ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                          dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                         dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                         9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                          `'      9XXXXXX(   )XXXXXXP      `'
                                   XXXX X.`v'.X XXXX
                                   XP^X'`b   d'`X^XX
                                   X. 9  `   '  P )X
                                   `b  `       '  d'
                                    `             '
  
   [ TARGETS ]                                                 [ CAPABILITIES ]
   >> Lab-DC01  :: Windows Server 2022 (AD/CS/SQL)             >> AD CS/PKI Abuse
   >> Lab-Web01 :: Debian 12 (Docker/K3s/AI)                   >> Golden Ticket/Kerberoasting
                                                               >> SQL Injection & LOLBins
   [ STATUS ]                                                  >> Insecure AI & Container Breakout
   >> SYNC: [████████████████████] 100%
   >> AMSI: [BYPASSED]
   >> EDR:  [BLINDED]


## 💀 WHAT IS THIS?

**Modern Kill Lab** is a fully automated offensive security cyber range that deploys a complete Active Directory environment riddled with real-world vulnerabilities. 

Two targets. One domain. Countless attack paths.

Built for red teamers, pentesters, and security researchers who want to sharpen their skills on infrastructure that fights back.

---

## 🎯 TARGET ALPHA: Lab-DC01

**Windows Server 2022 // Domain Controller**

| Vulnerability Class |
|---------------------|
| Kerberos Authentication Attacks |
| Certificate Services Abuse |
| Web Application Exploitation |
| Credential Theft & Dumping |
| Security Control Bypass |
| Living Off The Land |
| Persistence Mechanisms |

---

## 🎯 TARGET BRAVO: Lab-Web01

**Debian 12 Linux // Domain-Joined Server**

| Vulnerability Class |
|---------------------|
| Network Service Exploitation |
| Command Injection |
| Container Escape |
| Kubernetes Compromise |
| Linux Privilege Escalation |
| API Security Flaws |
| Secrets Discovery |

---

## ⚡ DEPLOYMENT

### Requirements

| Component | Minimum |
|-----------|---------|
| RAM | 16 GB |
| Disk | 100 GB free |
| CPU | VT-x / AMD-V enabled |
| OS | Windows, macOS, or Linux |

### Execution

```bash
git clone <repo_url>
cd ModernKillLab
python3 master_build.py
```

The builder automatically handles:
- Packer & VirtualBox installation
- ISO downloads
- VM provisioning and configuration
- Domain join orchestration
- Internal network setup

### Build Timeline

| Phase | Time |
|-------|------|
| DC01 Build | ~45-60 min |
| DC01 Initialize | ~3 min |
| Web01 Build + Domain Join | ~20-30 min |
| **Total** | **~70-90 min** |

---

## 📖 NEXT STEPS

After deployment completes, open **`LAB_GUIDE.md`** for:

- Network topology & credentials
- Complete vulnerability catalog
- Step-by-step exploitation walkthroughs  
- Detailed technical explanations
- Tool recommendations

---

## ⚠️ LEGAL

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   FOR AUTHORIZED EDUCATIONAL USE AND PENETRATION TESTING ONLY             ║
║                                                                           ║
║   Unauthorized access to computer systems is illegal.                     ║
║   The creators assume no liability for misuse.                            ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

**Let the hunt begin.** 🔥
