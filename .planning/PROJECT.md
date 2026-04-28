# SimpleVault — Bóveda colaborativa segura

## Visión

Webapp tipo password manager + notas seguras, con foco **obsesivo** en seguridad real. Personal y colaborativa (vaults compartidos), production-hardened contra adversario targeted, no MVP de juguete.

**The one thing that must work:** Un usuario puede guardar credenciales y notas sensibles, compartir un vault con otra persona, y tener garantía verificable de que **nadie excepto los miembros con su contraseña** —ni el operador del servidor, ni un atacante con DB dump, ni un insider— puede leer el contenido.

## Audiencia

- **v1**: ≤50 usuarios, uso personal + amigos/familia.
- Sin compliance formal (GDPR/SOC2 no aplica al volumen actual), pero buenas prácticas alineadas con OWASP ASVS L2.
- Operador (yo) hostea infra propia (self-hosted Docker + VPS).

## Threat model (resumen — detalle en `.planning/security/THREAT-MODEL.md`)

- **Adversario asumido**: Targeted attacker. Web-skilled, motivado, con tiempo. Usa phishing, credential stuffing, exploits de dependencias conocidas, abuso de features. Puede comprometer email del usuario, puede obtener DB dump leak, puede hacer MITM en redes hostiles.
- **Adversario NO asumido (out of scope)**: Nation-state / APT, side-channels de hardware, ataques físicos al device del usuario, supply-chain compromise activo del kernel del SO.
- **Servidor es semi-trusted**: backend nunca debe ver plaintext de credenciales/páginas. Pero confiamos en que sirve frontend correcto (defendido con SRI + CSP).

## Core decisions (load-bearing — no cambiar sin re-threat-model)

| Decisión | Elegido | Razón |
|---|---|---|
| Encryption | E2E client-side (XChaCha20-Poly1305) | Backend nunca ve plaintext. Único modelo defendible para producto que se vende como "seguro". |
| KDF | Argon2id (m=64MB, t=3, p=1 mínimo, calibrado por device) | Estándar de la industria, GPU-resistant. |
| Master password recovery | **Recovery code BIP39 generado en signup** (24 palabras) | Sin backdoor server-side. Si pierde ambos → data loss aceptado. |
| 2FA | **WebAuthn (passkeys/YubiKey) + TOTP** ambos. Opcional para vault personal, **OBLIGATORIO** para crear/unirse a vault compartido. | Phishing-resistant por diseño en vaults compartidos (mayor blast radius). |
| Sharing model | Per-user key wrapping. Cada miembro tiene su propio user-KEK; vault-DEK se wrappea con cada user-KEK. | Permite revocación sin re-cifrar el vault entero (rotando vault-DEK). |
| Vault invite | **Token HMAC-firmado, single-use, 24h, vinculado a email + OOB approval del creator** | Defensa en profundidad: link leak no basta, requiere email + acción del creator. |
| Eliminación | Consenso unánime de miembros activos. Timeout 30d sin respuesta → creator override (notif 7d antes, audit log inmutable). | Resuelve deadlock. Conserva intent de "decisión grupal". |
| Página doble-lock | page-DEK random, wrapped por page-KEK (Argon2id de page-password) **Y** por master-KEK | Doble lock real; opción de reset si olvida page-pwd (auditable, pierde el doble lock). |
| Audit log | Hash chain por vault: `H(prev_hash ∥ entry)` | Tamper-evident detectable en O(n). Verificación en cada lectura + cron diario. |
| Rich-text editor | TipTap (ProseMirror) + sanitize-html en render | Schema estricto = XSS surface mínima. JSON output, no HTML soup. |
| ORM | Drizzle | SQL-first, queries auditables, sin runtime engine opaco. Crítico para audit log integrity. |
| Hosting | **Self-hosted Docker + VPS** (Caddy reverse proxy + Let's Encrypt, fail2ban, ufw) | Soberanía total, zero third-party trust. Requiere `infra-deployment-auditor` como gate top priority. |
| Backups | Server snapshots cifrados (Postgres pg_dump cifrado con clave operador, restic → S3-compatible) + export client-side cifrado con master | Cubre crash de DB **y** "user perdió acceso pero tiene archivo offline". |

## Stack obligatorio

- **Monorepo**: Turborepo + pnpm workspaces
- **Backend**: NestJS + PostgreSQL + Drizzle ORM
- **Frontend**: Next.js 15 (App Router) + TypeScript + React 19
- **Crypto (client)**: WebCrypto API + libsodium-wrappers (XChaCha20-Poly1305, Argon2id via `argon2-browser` con WASM)
- **Crypto (server)**: `node:crypto` + `argon2` (node-argon2)
- **UI**: TailwindCSS + Aceternity UI + Framer Motion
- **Auth**: Argon2id (passwords), JWT short-lived (15min) + refresh token rotation en httpOnly+Secure+SameSite=Strict cookies, WebAuthn (`@simplewebauthn/*`), TOTP (`otplib`)
- **Validation**: Zod en TODOS los DTOs (cliente y servidor)
- **Rate limiting**: `@nestjs/throttler` + Redis (token bucket por IP + por user)
- **Audit log**: tabla append-only en Postgres, hash chain firmado con HMAC-SHA256
- **Deploy**: Docker + docker-compose, VPS (Hetzner / DigitalOcean / Vultr), Caddy reverse proxy
- **Monitoring**: Prometheus + Grafana self-hosted, alerts en eventos de seguridad (5xx burst, brute-force, audit chain break)

## UI/UX

- Mobile-first, sentirse nativo en móvil (touch targets ≥44px, gestures naturales)
- Diseño minimalista premium (Aceternity components con sobriedad)
- Dark mode por default, light mode opcional
- Animaciones sutiles con Framer Motion (≤300ms, ease-out)
- Mostrar siempre estado de cifrado / sesión / 2FA en UI (transparencia construye confianza)

## Out of scope para v1 (explícito)

- Browser extension (autofill)
- Mobile native apps (iOS/Android)
- File attachments cifrados
- TOTP/2FA secrets stored como entries del vault
- Compartir individual de items (sólo vaults completos)
- Emergency contacts / herencia (v2)
- Billing / multi-tenant / SSO / SCIM (no aplica a "personal + familia")
- Public registration (signup será por código de invite del operador)
- Self-service operator onboarding (un solo operador, yo)

## Success criteria (cómo sabemos que v1 está hecho)

1. Operador puede deployar con `docker compose up -d` en VPS limpio + DNS apuntado, en <30 min
2. Usuario puede registrarse (con código de invite del operador), generar/guardar recovery code, hacer login, agregar credencial, agregar página
3. Usuario puede crear vault compartido, invitar a otro usuario por email + aprobar OOB, otro usuario acepta y ve los items con SU password
4. Audit log refleja todas las acciones con IP/device/timestamp y la cadena hash verifica
5. Eliminación de vault compartido requiere voto de todos; timeout + override funcionan según spec
6. Master password reset con recovery code BIP39 funciona end-to-end
7. **TODOS los 12 auditores de seguridad firman OK** sin findings High/Critical abiertos
8. Pentester/red-team agent no consigue romper auth, escalar privilegios, ni leer plaintext del DB dump
9. Backup + restore testeado: tirar VPS, levantar nuevo desde snapshot, todos los usuarios siguen accediendo a sus vaults
