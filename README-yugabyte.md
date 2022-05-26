## steps to recreate current issue (May 26, 2022)

### current error
`unknown: error #0: ERROR: cannot drop index target_tcp_pkey because constraint target_tcp_pkey on table target_tcp requires it (SQLSTATE 2BP01)`

### install/start yugabyte
### create database and grant privs
```
create database watchtower;
grant all privileges on database watchtower to boundary;
create user boundary with password 'boundary';
```
### build/install this fork of boundary:
```
git clone https://github.com/jimlambrt/boundary.git`
git switch jimlambrt-yugabyte
make build
make install
```

### initialize the boundary database
```
boundary database init --config=boundary.hcl
```

### Migration that fails

https://github.com/jimlambrt/boundary/blob/jimlambrt-yugabyte/internal/db/schema/migrations/oss/postgres/1/01_server_tags_migrations.up.sql