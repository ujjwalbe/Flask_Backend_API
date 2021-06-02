-- SQL script to bootstrap the DB:
--
CREATE ROLE db_userr LOGIN PASSWORD 'secure_password';

--
--
CREATE DATABASE flask_db1;
GRANT ALL PRIVILEGES ON flask_db.* TO db_user;
FLUSH PRIVILEGES;
--
USE flask_db;
--
CREATE TABLE CUSTOMERS(
    ID  SERIAL PRIMARY KEY,
    NAME           TEXT      NOT NULL,
    EMAIL          TEXT      NOT NULL,
    PASSWORD       TEXT      NOT NULL,
    LAST_SIGNIN_ATTEMPT TIMESTAMP NULL,
    FAILED_SIGNIN_ATTEMPT INT NULL,
    TASK_GROUP_ID INT NULL);


CREATE TABLE TASKS(ID SERIAL PRIMARY KEY, GROUP_ID INT NOT NULL, DESCRIPTION TEXT NOT NULL);


INSERT INTO TASKS(GROUP_ID, DESCRIPTION)
 VALUES (3, 'Draw a circle and fill with green color'),
    (3, 'Draw a rectangle and fill with red color'),
    (3, 'Draw circle and fill with green color'),
    (1, 'Collect timber and build dog house'),
    (1, 'Collect timber and build cat house'),
    (1, 'Collect timber and build bird house'),
    (1, 'Collect timber and build hamster house'),
    (2, 'Go to the market and bring a packet of milk'),
    (2, 'Go to the market and bring a toy'),
    (2, 'Go to the market and bring an ice cream');





