package main

import (
	"database/sql"
	"log"
	"strings"
)

var migrations = []func() error{
	migrateCreateUser,
	migrateCreateEmail,
	migrateAddContacts,
	migratePasswordHash,
	migrateEmailRefactor,
	migrateLengthenSubject,
	migrateShortenToken,
	migrateAddUserEmailAddress,
	migrateCreateNameResolution,
	migrateMakeNameResolutionUnique,
	migrateEmailThreading,
	migrateBoxAddForeignKey,
	migrateBoxAddError,
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

func migrateEmailRefactor() error {

	// Migration of existing data
	// Load everything onto memory, wipe table, then reinsert.
	type OldEmailRow struct {
		// Columns from the old email table
		UnixTime                                            int64
		MessageID, From, To, CipherSubject, CipherBody, Box string
		PubHashTo, PubHashFrom                              string

		// Convenience. Aggregate {<pub_hash> -> [<box1>,<box2>]} here
		Boxes map[string][]string
	}
	rows, err := db.Query(`SELECT
        m.unix_time, m.message_id, m.from_email, m.to_email,
        m.cipher_subject, m.cipher_body, m.box,
        m.pub_hash_to, m.pub_hash_from
		FROM email as m`)
	if err != nil {
		return err
	}
	oldEmails := map[string]*OldEmailRow{}
	for rows.Next() {
		oldEmail := &OldEmailRow{}
		err = rows.Scan(
			&oldEmail.UnixTime,
			&oldEmail.MessageID,
			&oldEmail.From,
			&oldEmail.To,
			&oldEmail.CipherSubject,
			&oldEmail.CipherBody,
			&oldEmail.Box,
			&oldEmail.PubHashTo,
			&oldEmail.PubHashFrom,
		)
		if err != nil {
			return err
		}
		if oldEmails[oldEmail.MessageID] == nil {
			oldEmails[oldEmail.MessageID] = oldEmail
			oldEmail.Boxes = map[string][]string{}
		}
		boxesForRecipient := oldEmails[oldEmail.MessageID].Boxes[oldEmail.PubHashTo]
		if boxesForRecipient == nil {
			oldEmails[oldEmail.MessageID].Boxes[oldEmail.PubHashTo] = []string{oldEmail.Box}
		} else {
			boxesForRecipient = append(boxesForRecipient, oldEmail.Box)
		}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS new_email (
        message_id     CHAR(40) NOT NULL,
        unix_time      BIGINT NOT NULL,
        from_email     VARCHAR(254) NOT NULL,
        to_email       TEXT NOT NULL,
        cipher_subject VARCHAR(1500) NOT NULL,
        cipher_body    LONGTEXT NOT NULL,

        primary key (message_id)
    )`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS box (
        id         BIGINT NOT NULL AUTO_INCREMENT,
        message_id CHAR(40) NOT NULL,
        address    VARCHAR(254) NOT NULL,
        box        ENUM('inbox','outbox','sent','archive','trash','outbox-sent','outbox-processing') NOT NULL,
        unix_time  BIGINT NOT NULL,
        
        PRIMARY KEY (id),
        INDEX (address, box, unix_time),
        INDEX (address, message_id)
    )`)
	if err != nil {
		return err
	}

	// Reinsert everything from oldEmails
	for _, oldEmail := range oldEmails {
		// insert row into email
		_, err := db.Exec(`INSERT INTO new_email
            (message_id, unix_time, from_email, to_email, cipher_subject, cipher_body)
            VALUES (?,?,?,?,?,?)`,
			oldEmail.MessageID,
			oldEmail.UnixTime,
			oldEmail.From,
			oldEmail.To,
			oldEmail.CipherSubject,
			oldEmail.CipherBody,
		)
		if err != nil {
			return err
		}
		// insert row(s) into box
		var sentToSelf bool = false
		for pubHashTo, boxes := range oldEmail.Boxes {
			addressTo := pubHashTo + "@scramble.io"
			if oldEmail.PubHashFrom == pubHashTo && len(boxes) == 1 && boxes[0] != "sent" {
				sentToSelf = true
			}
			for _, box := range boxes {
				_, err := db.Exec(`INSERT INTO box
                    (message_id, address, box, unix_time)
                    VALUES (?,?,?,?)`,
					oldEmail.MessageID,
					addressTo,
					box,
					oldEmail.UnixTime,
				)
				if err != nil {
					return err
				}
			}
		}
		// if sender also sent to self, there was no
		// corresponding "sent" entry, so create one.
		if sentToSelf {
			_, err := db.Exec(`INSERT INTO box
				(message_id, address, box, unix_time)
				VALUES (?,?,?,?)`,
				oldEmail.MessageID,
				oldEmail.From,
				"sent",
				oldEmail.UnixTime,
			)
			if err != nil {
				return err
			}
		}
	}

	_, err = db.Exec(`DROP TABLE email`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`RENAME TABLE new_email to email`)
	if err != nil {
		return err
	}

	return err
}

func migrateLengthenSubject() error {
	_, err := db.Exec(`ALTER TABLE email MODIFY cipher_subject TEXT`)
	return err
}

func migrateShortenToken() error {
	_, err := db.Exec(`ALTER TABLE user MODIFY token VARCHAR(64)`)
	return err
}

func migrateAddUserEmailAddress() error {
	_, err := db.Exec(`ALTER TABLE user ADD COLUMN email_host VARCHAR(254) NOT NULL DEFAULT ""`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE user SET email_host = ?`, GetConfig().SmtpMxHost)
	return err
}

func migrateCreateNameResolution() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS name_resolution (
		name           VARCHAR(64),
		host           VARCHAR(255),
		hash           CHAR(16),
		index (host, name)
    )`)
	if err != nil { return err }

	// Convert hash addresses in the database to name addresses
	rows, err := db.Query(`SELECT token, email_host, public_hash FROM user`)
	if err != nil { return err }
	convertMap := map[string]string{} // hashAddress -> nameAddress
	for rows.Next() {
		var token, emailHost, pubHash string
		err := rows.Scan(&token, &emailHost, &pubHash)
		if err != nil { return err }
		convertMap[pubHash+"@"+emailHost] = token+"@"+emailHost
	}
	// Convert all address rows in box
	rows, err = db.Query(`SELECT id, address FROM box`)
	if err != nil { return err }
	for rows.Next() {
		var id, address string
		err := rows.Scan(&id, &address)
		if err != nil { return err }
		var newAddress = convertMap[address]
		if newAddress == "" {
			log.Printf("Could not translate address in box: %s %s", id, address)
			continue
		}
		_ ,err = db.Exec(`UPDATE box SET address=? WHERE id=?`,
			newAddress, id)
		if err != nil { return err }
	}
	// Convert all address rows in email
	rows, err = db.Query(`SELECT message_id, from_email, to_email FROM email`)
	if err != nil { return err }
	for rows.Next() {
		var id, fromEmail, toEmail string
		err := rows.Scan(&id, &fromEmail, toEmail)
		if err != nil { return err }
		var newFromEmail = convertMap[fromEmail]
		if newFromEmail == "" {
			log.Printf("Could not translate from address in email: %s %s", id, fromEmail)
			continue
		}
		var newToEmailArray []string
		for _, toEmail := range strings.Split(toEmail, ",") {
			var newToEmail = convertMap[toEmail]
			if newToEmail == "" {
				log.Printf("Could not translate to address in email: %s %s", id, toEmail)
				continue
			}
			newToEmailArray = append(newToEmailArray, newToEmail)
		}
		var newToEmail = strings.Join(newToEmailArray, ",")
		_ ,err = db.Exec(`UPDATE email SET from_email=?, to_email=? WHERE message_id=?`,
			newFromEmail, newToEmail, id)
		if err != nil { return err }
	}

	return err
}

func migrateMakeNameResolutionUnique() error {
	// some MySQL versions will crap out when dropping/adding the same index in one line.
	_, err := db.Exec(`ALTER TABLE name_resolution DROP INDEX host`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE name_resolution ADD UNIQUE INDEX (host, name)`)
	return err
}

func migrateEmailThreading() error {
	_, err := db.Exec(`ALTER TABLE email `+
		`MODIFY message_id VARCHAR(255) NOT NULL, `+
		`ADD COLUMN ancestor_ids VARCHAR(10240), `+
		`ADD COLUMN thread_id VARCHAR(255) NOT NULL`)
	if err != nil { return err }
	_ ,err = db.Exec(`UPDATE email `+
		`SET message_id = CONCAT(message_id, "@", ?)`,
		GetConfig().SmtpMxHost)
	if err != nil { return err }
	_ ,err = db.Exec(`UPDATE email SET thread_id = message_id`)
	if err != nil { return err }
	_, err = db.Exec(`ALTER TABLE box `+
		`MODIFY message_id VARCHAR(255) NOT NULL, `+
		`ADD COLUMN thread_id VARCHAR(255) NOT NULL`)
	if err != nil { return err }
	_ ,err = db.Exec(`UPDATE box `+
		`SET message_id = CONCAT(message_id, "@", ?)`,
		GetConfig().SmtpMxHost)
	if err != nil { return err }
	_, err = db.Exec(`UPDATE box SET thread_id = message_id`)
	if err != nil { return err }
	_, err = db.Exec(`ALTER TABLE box `+
		`ADD INDEX (address, box, thread_id, unix_time)`)
	return err
}

func migrateBoxAddForeignKey() error {
	_, err := db.Exec(`ALTER TABLE box ADD FOREIGN KEY (message_id) REFERENCES email(message_id)`)
	return err
}

func migrateBoxAddError() error {
	_, err := db.Exec(`ALTER TABLE box ADD COLUMN error TEXT`)
	return err
}
