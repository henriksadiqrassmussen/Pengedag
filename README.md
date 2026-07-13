# Pengedag v1.6.0 - Fast Backend med PostgreSQL

Dette er første rigtige database-backend til Pengedag.

Den gemmer data i PostgreSQL i stedet for JSON/demo-filer.

## Railway

Start Command:

```txt
npm run start
```

Miljøvariabler:

```txt
NODE_ENV=production
DATABASE_URL=Railway PostgreSQL database URL
CORS_ORIGIN=*
```

## Test

```txt
/health
/api/mobile/routes
/api/mobile/time-entries
/api/admin/audit-log
```
