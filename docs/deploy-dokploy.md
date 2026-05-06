# SimpleVault — Deploy en Dokploy

## Stack

- **Monorepo**: pnpm 9 + Turborepo
- **API**: NestJS (Node 22), ORM Drizzle, PostgreSQL + Redis
- **Web**: Next.js 15 (standalone output), React 19
- **Auth**: JWT propio + WebAuthn (sin Auth.js)
- **Hosting**: Dokploy (Docker Compose deployment)
- **DNS**: Cloudflare, dominio `runadev.com`
- **DB/Redis**: servicios compartidos del infra Dokploy

---

## 1. Estructura del Dockerfile (monorepo)

Hay **dos Dockerfiles**, uno por app. El contexto de build es la **raíz del monorepo** en ambos casos:

```
apps/api/Dockerfile    → build context: .
apps/web/Dockerfile    → build context: .
```

Cada uno tiene 3 stages:

| Stage  | Qué hace                                                       |
|--------|----------------------------------------------------------------|
| `deps` | Instala todo con pnpm (lockfile frozen, incluyendo devDeps)    |
| `build`| Compila los packages internos + la app; genera el bundle prod  |
| `runner`| Imagen mínima `node:22-alpine` con tini, usuario `app` no-root|

**Importante**: el build de la API corre `pnpm --filter @simplevault/api deploy --prod /out` para generar un bundle autocontenido, y luego copia manualmente la carpeta `drizzle/` de migraciones al bundle porque `pnpm deploy` no la incluye automáticamente:

```dockerfile
RUN cp -R /repo/packages/db/drizzle /out/node_modules/@simplevault/db/drizzle
```

Sin ese `cp` el container arranca y falla buscando las migraciones.

**Las migraciones** se corren automáticamente al arrancar via `migrate-then-start.sh`:

```sh
cd /app/node_modules/@simplevault/db
node ./dist/migrate.js   # Drizzle — idempotente
cd /app
exec node dist/main.js
```

El `cd` al directorio del package es necesario porque `migrate.js` usa la ruta relativa `./drizzle` como `migrationsFolder`.

---

## 2. Base de datos y Redis

SimpleVault necesita **Postgres + Redis**. Opciones en Dokploy:

**Opción A (recomendada): reutilizar el infra compartido**

Desde la terminal del servicio Postgres en Dokploy:

```sql
psql -U postgres -c "CREATE DATABASE simplevault;"
```

Para Redis, usar el servicio Redis compartido si existe, o crear uno nuevo en Dokploy (servicio Redis, imagen `redis:7.4-alpine`).

**DATABASE_URL resultante:**

```
postgresql://postgres:<pass>@infra-<id>:5432/simplevault
```

**REDIS_URL resultante:**

```
redis://infra-redis-<id>:6379
```

Los nombres de host son los nombres de servicio internos de Docker (visibles en Dokploy bajo cada servicio).

---

## 3. Secretos — generación

**Todos los secretos son obligatorios**. Generarlos en la VPS o localmente:

```bash
# JWT_SECRET (mínimo 32 bytes)
openssl rand -base64 32

# SERVER_CHAIN_SECRET
openssl rand -base64 48

# SERVER_IP_HASH_SECRET
openssl rand -base64 32

# SERVER_ARGON_SALT (exactamente 16 bytes → 24 chars base64)
openssl rand -base64 16

# SERVER_INVITE_SECRET
openssl rand -base64 48

# SERVER_RECOVERY_HMAC_SECRET
openssl rand -base64 48
```

**Guardarlos en un lugar seguro** — no se pueden regenerar sin invalidar datos existentes (la sal de Argon2 y los HMAC son deterministicos sobre los datos almacenados).

---

## 4. Configuración en Dokploy

### Tipo de deployment: Docker Compose

SimpleVault usa dos servicios (api + web) que dependen entre sí por red interna. El tipo correcto en Dokploy es **Docker Compose**, no "Application".

- Proyecto: `production`
- Nombre: `simplevault`
- Source: GitHub → repo `germankatz/simplevault`, branch `main`
- **Build Type: `Docker Compose`**
- Compose file: `docker-compose.yml` (raíz del repo)

### Variables de entorno (API)

```env
NODE_ENV=production
PORT=3001

DATABASE_URL=postgresql://postgres:<pass>@infra-<id>:5432/simplevault
REDIS_URL=redis://infra-redis-<id>:6379

JWT_SECRET=<generado>
SERVER_CHAIN_SECRET=<generado>
SERVER_IP_HASH_SECRET=<generado>
SERVER_ARGON_SALT=<generado 16B>
SERVER_INVITE_SECRET=<generado>
SERVER_RECOVERY_HMAC_SECRET=<generado>

# Calibrar en la VPS prod con: pnpm cli argon2 calibrate
# Target 750ms. Estos son los defaults de dev — cambiarlos.
ARGON2_MEMORY_KIB=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=1

CORS_ORIGINS=https://pass.runadev.com

WEBAUTHN_RP_ID=pass.runadev.com
WEBAUTHN_RP_NAME=SimpleVault
WEBAUTHN_ORIGIN=https://pass.runadev.com

# TTLs por defecto — se pueden dejar igual
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=2592000
STEP_UP_TOKEN_TTL=120
SESSION_EPOCH_CACHE_TTL=60

# Rate limits por defecto (revisar para prod)
GLOBAL_RATE_LIMIT=1000
LOGIN_IP_RATE_LIMIT=5
LOGIN_EMAIL_RATE_LIMIT=10
SIGNUP_RATE_LIMIT=3
REFRESH_IP_RATE_LIMIT=60
LOGOUT_IP_RATE_LIMIT=60
AUTH_PARAMS_RATE_LIMIT=100
INVITE_REDEEM_RATE_LIMIT=30
ME_RATE_LIMIT=100
TWOFA_REGISTER_RATE_LIMIT=10
TWOFA_WEBAUTHN_AUTH_RATE_LIMIT=30

LOG_LEVEL=info
```

### Variables de entorno (Web)

```env
NODE_ENV=production
PORT=3000
HOSTNAME=0.0.0.0
NEXT_PUBLIC_API_URL=https://api.pass.runadev.com
```

`NEXT_PUBLIC_API_URL` es la URL **pública** de la API (lo que ve el browser del usuario), no la URL interna de Docker. Requiere el subdominio de la API expuesto via Traefik.

---

## 5. DNS con Cloudflare

Zona `runadev.com` → DNS → dos registros A:

| Type | Name    | Content    | Proxy      |
|------|---------|------------|------------|
| A    | pass    | IP del VPS | DNS only ☁ |
| A    | api.pass| IP del VPS | DNS only ☁ |

**Usar "DNS only" (nube gris)**, no proxy naranja. Con proxy activo, Cloudflare termina el TLS antes de llegar a Dokploy y Traefik no puede emitir el certificado Let's Encrypt.

En Dokploy → tab **Domains**:
- Servicio `web`: `pass.runadev.com` con HTTPS
- Servicio `api`: `api.pass.runadev.com` con HTTPS

---

## 6. Argon2 — calibración en prod

Los valores del `.env` de dev son deliberadamente bajos (para que el wizard de setup corra rápido en local). En producción el target es **~750ms por operación de hash**.

Una vez que la VPS esté corriendo:

```bash
# Entrar al container de la API
docker exec -it <container_api_id> sh

# Correr el calibrador
cd /app && node dist/main.js argon2 calibrate   # si el CLI está integrado
# o via el paquete cli si está instalado por separado
```

Actualizar las variables `ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS`, `ARGON2_PARALLELISM` con los valores devueltos y hacer redeploy.

---

## 7. Acceso al container para debugging

El runner usa `node:22-alpine`. El Dockerfile **no instala bash** por defecto en simplevault (solo `tini` y `curl`). Usar `sh`:

```bash
docker exec -it <container_id> sh
# El WORKDIR del container es /app
# Al entrar via exec estás en / — siempre: cd /app
```

O directamente:

```bash
docker exec -w /app <container_id> sh
```

---

## 8. Primer deploy — checklist

- [ ] Base de datos `simplevault` creada en Postgres compartido
- [ ] Redis disponible y accesible desde la red de Docker
- [ ] Todos los secretos generados y cargados en Dokploy env vars
- [ ] DNS A records creados en Cloudflare (DNS only)
- [ ] Dominios registrados en Dokploy con HTTPS
- [ ] `NEXT_PUBLIC_API_URL` apunta al subdominio público de la API
- [ ] `WEBAUTHN_RP_ID` y `WEBAUTHN_ORIGIN` apuntan al dominio prod de la web
- [ ] `CORS_ORIGINS` contiene el dominio prod de la web
- [ ] Deploy inicial corrido — verificar logs que las migraciones pasen
- [ ] Argon2 calibrado y env vars actualizadas con valores prod

---

## Errores frecuentes y sus fixes

| Error | Causa | Fix |
|-------|-------|-----|
| `Cannot find module ./drizzle` al arrancar la API | Carpeta de migraciones no copiada al bundle | Verificar el `cp -R drizzle` en el Dockerfile |
| `pnpm install` falla con "workspace not found" | Context de build incorrecto (no es la raíz) | Build context debe ser `.` (raíz del monorepo), no `apps/api` |
| Certificado Let's Encrypt no emite | Cloudflare en modo proxy (naranja) | Cambiar a DNS only (nube gris) |
| WebAuthn falla con "invalid origin" | `WEBAUTHN_ORIGIN` no coincide con la URL del browser | Debe ser exactamente `https://pass.runadev.com` sin trailing slash |
| `NEXT_PUBLIC_API_URL` no disponible en browser | Variable no seteada antes del build de Next.js | Es una var de build-time — setearla en Dokploy antes del primer build |
| Redis connection refused | Container web intenta conectar Redis (no debería) | Solo la API conecta Redis; verificar que web no tenga REDIS_URL seteada |
| Argon2 muy lento o muy rápido en prod | Valores dev copiados sin calibrar | Correr `argon2 calibrate` en la VPS y actualizar los env vars |
