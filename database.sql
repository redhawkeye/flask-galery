CREATE TABLE `creds` (
  `idn` int NOT NULL AUTO_INCREMENT,
  `fnam` varchar(100) DEFAULT NULL,
  `lnam` varchar(100) DEFAULT NULL,
  `hash` varchar(100) DEFAULT NULL,
  `salt` int DEFAULT NULL,
  `ctim` bigint DEFAULT NULL,
  `utim` bigint DEFAULT NULL,
  `rol` int DEFAULT NULL,
  `unam` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`idn`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO creds (fnam,lnam,hash,salt,ctim,utim,rol,unam) VALUES ('Galery','Admin','$2a$10$bwCmhcEFiXrEnUFxHXuxn.ncgsnSSN6rpFv7PfSFjpYvsFrROqsMa',137137,1711349116,1711349116,0,'admin');
