CREATE TABLE IF NOT EXISTS USER
(
    id       INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    name     VARCHAR(10),
    password VARCHAR(100)
    )
    CHARSET utf8;

CREATE TABLE IF NOT EXISTS ROLE
(
    id   INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    name VARCHAR(10)
    )
    CHARSET utf8;

CREATE TABLE IF NOT EXISTS ROLE_USER
(
    user_id INT,
    role_id INT
)
    CHARSET utf8;


INSERT INTO `ROLE` (`id`, `name`)
SELECT '1',
       'ROLE_ADMIN'
FROM dual
WHERE NOT exists(SELECT id
                 FROM `ROLE`
                 WHERE id = '1');
INSERT INTO `ROLE` (`id`, `name`)
SELECT '2',
       'ROLE_USER'
FROM dual
WHERE NOT exists(SELECT id
                 FROM `ROLE`
                 WHERE id = '2');
-- 密码是admin
INSERT INTO `USER` (`id`, `password`, `name`)
SELECT '1',
       '$2a$10$0eA9i4hBVfPNiVz3u4Cg0uF0fEgjCK1EA7tenOXZ..I1W1HtYps.q',
       'admin'
FROM dual
WHERE NOT exists(SELECT id
                 FROM `USER`
                 WHERE id = '1');
INSERT INTO `USER` (`id`, `password`, `name`)
-- 密码是user
SELECT '2',
       '$2a$10$8Oht.MIQTMVjjA.lf6hQL./pHHI0GnQC.BC9fBsvPWXaeathXQlry',
       'user'
FROM dual
WHERE NOT exists(SELECT id
                 FROM `USER`
                 WHERE id = '2');


INSERT INTO `ROLE_USER` (`user_id`, `role_id`)
SELECT '1',
       '1'
FROM dual
WHERE NOT exists(SELECT user_id
                 FROM `ROLE_USER`
                 WHERE user_id = '1');
INSERT INTO `ROLE_USER` (`user_id`, `role_id`)
SELECT '2',
       '2'
FROM dual
WHERE NOT exists(SELECT user_id
                 FROM `ROLE_USER`
                 WHERE user_id = '2');




