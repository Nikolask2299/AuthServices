CREATE TABLE IF NOT EXISTS users (
    guid INT8 NOT NULL UNIQUE PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    ip CIDR NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    refr_hash TEXT NOT NULL
)