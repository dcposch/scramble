package main

import (
	"database/sql"
	"log"
)

var migrations = []func() error{
	migrateCreateUser,
	migrateCreateEmail,
	migrateAddContacts,
	migratePasswordHash,
}

func migrateDb() {
	// create the table, if needed
	_, err := db.Exec(`create table if not exists migration (
        version int not null
    ) engine=InnoDB`)
	if err != nil {
		panic(err)
	}

	// what version are we at? lock it
	var version int
	err = db.QueryRow("select version from migration").Scan(&version)
	if err == sql.ErrNoRows {
		version = 0
	} else if err != nil {
		panic(err)
	}

	// apply migrations
	for ; version < len(migrations); version++ {
		log.Printf("Migrating DB version %d to %d\n", version, version+1)
		err = migrations[version]()
		if err != nil {
			panic(err)
		}
		if version == 0 {
			_, err = db.Exec("insert into migration(version) values (?)", version+1)
		} else {
			_, err = db.Exec("update migration set version=?", version+1)
		}
	}
}

func migrateCreateUser() error {
	_, err := db.Exec(`create table if not exists user (
        token varchar(100) not null,
        password_hash char(40) not null,
        public_hash char(40) not null,
        public_key varchar(4000) not null,
        cipher_private_key varchar(4000) not null,

        primary key (token),
        unique index (public_hash)
    )`)
	return err
}

func migrateCreateEmail() error {
	_, err := db.Exec(`create table if not exists email (
        message_id char(40) not null,
        unix_time bigint not null,
        box enum ('inbox','outbox','sent','archive','trash') not null,

        from_email varchar(254) not null,
        to_email varchar(254) not null,

        pub_hash_from char(40),
        pub_hash_to char(40),
        cipher_subject varchar(1500) not null,
        cipher_body longtext not null,

        primary key (message_id, pub_hash_to),
        index (pub_hash_to, box),
        index (pub_hash_from)
    )`)
	return err
}

func migrateAddContacts() error {
	_, err := db.Exec(`alter table user add column cipher_contacts longtext`)
	return err
}

func migratePasswordHash() error {
	_, err := db.Exec(`alter table user 
        add column password_hash_old char(160) not null default "" 
        after password_hash`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`update user set password_hash_old=password_hash, password_hash=""`)
	return err
}
