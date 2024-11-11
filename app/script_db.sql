CREATE TABLE `countries` (
	`country_id` INTEGER NOT NULL AUTO_INCREMENT,
	`country_code` VARCHAR(2) DEFAULT NULL,
	`country_name` VARCHAR(100) DEFAULT NULL,
	PRIMARY KEY(`country_id`)
);


CREATE TABLE `scheme_operators` (
	`operator_id` INTEGER NOT NULL AUTO_INCREMENT,
	`tsl_id` INTEGER DEFAULT NULL,
	`operator_name` VARCHAR(100) DEFAULT NULL,
	`operator_address` TEXT DEFAULT NULL,
	`operator_email` VARCHAR(100) DEFAULT NULL,
	`operator_website` VARCHAR(255) DEFAULT NULL,
	`operator_role` VARCHAR(20) DEFAULT NULL,
	`pid_hash` VARCHAR(255) DEFAULT NULL,
	`country_id` INTEGER,
	PRIMARY KEY(`operator_id`)
);


CREATE TABLE `service_status_history` (
	`history_id` INTEGER NOT NULL AUTO_INCREMENT,
	`service_id` INTEGER DEFAULT NULL,
	`previous_status` VARCHAR(20) DEFAULT NULL,
	`status_start_date` TIMESTAMP DEFAULT NULL,
	PRIMARY KEY(`history_id`)
);


CREATE TABLE `trusted_lists` (
	`tsl_id` INTEGER NOT NULL AUTO_INCREMENT,
	`country_id` INTEGER DEFAULT NULL,
	`version` INTEGER DEFAULT NULL,
	`sequence_number` INTEGER DEFAULT NULL,
	`issue_date` TIMESTAMP DEFAULT NULL,
	`next_update` TIMESTAMP DEFAULT NULL,
	`status` VARCHAR(20) DEFAULT NULL,
	`signature` BINARY(255) DEFAULT NULL,
	`uri` VARCHAR(255) DEFAULT NULL,
	`pointers_to_other_tsl` VARCHAR(255),
	PRIMARY KEY(`tsl_id`)
);


CREATE TABLE `trusted_list_updates` (
	`update_id` INTEGER NOT NULL AUTO_INCREMENT,
	`tsl_id` INTEGER DEFAULT NULL,
	`update_date` TIMESTAMP DEFAULT NULL,
	`description` TEXT DEFAULT NULL,
	`signature` BINARY(255) DEFAULT NULL,
	PRIMARY KEY(`update_id`)
);


CREATE TABLE `trust_services` (
	`service_id` INTEGER NOT NULL AUTO_INCREMENT,
	`tsp_id` INTEGER DEFAULT NULL,
	`service_type` VARCHAR(50) DEFAULT NULL,
	`service_name` VARCHAR(100) DEFAULT NULL,
	`digital_identity` BINARY(255) DEFAULT NULL,
	`status` VARCHAR(20) DEFAULT NULL,
	`status_start_date` TIMESTAMP DEFAULT NULL,
	`uri` VARCHAR(255) DEFAULT NULL,
	`general` VARCHAR(255),
	`qualifier` VARCHAR(255),
	`qualificationElement` VARCHAR(255),
	`criteriaList` VARCHAR(255),
	`takenOverBy` VARCHAR(255),
	PRIMARY KEY(`service_id`)
);


CREATE TABLE `trust_service_providers` (
	`tsp_id` INTEGER NOT NULL AUTO_INCREMENT,
	`tsl_id` INTEGER DEFAULT NULL,
	`name` VARCHAR(100) DEFAULT NULL,
	`trade_name` VARCHAR(100) DEFAULT NULL,
	`address` TEXT DEFAULT NULL,
	`contact_email` VARCHAR(100) DEFAULT NULL,
	PRIMARY KEY(`tsp_id`)
);


ALTER TABLE `trusted_lists`
ADD FOREIGN KEY(`country_id`) REFERENCES `countries`(`country_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `trust_service_providers`
ADD FOREIGN KEY(`tsp_id`) REFERENCES `trusted_lists`(`tsl_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `trusted_list_updates`
ADD FOREIGN KEY(`tsl_id`) REFERENCES `trusted_lists`(`tsl_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `trust_services`
ADD FOREIGN KEY(`tsp_id`) REFERENCES `trust_service_providers`(`tsp_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `service_status_history`
ADD FOREIGN KEY(`service_id`) REFERENCES `trust_services`(`service_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `scheme_operators`
ADD FOREIGN KEY(`tsl_id`) REFERENCES `trusted_lists`(`tsl_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;
ALTER TABLE `scheme_operators`
ADD FOREIGN KEY(`country_id`) REFERENCES `countries`(`country_id`)
ON UPDATE NO ACTION ON DELETE NO ACTION;