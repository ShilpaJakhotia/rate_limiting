DROP TABLE IF EXISTS TBL_USER_DATA;

CREATE TABLE TBL_USER_DATA (
  id INT AUTO_INCREMENT  PRIMARY KEY,
  user_name VARCHAR(250) NOT NULL,
  pass VARCHAR(250) NOT NULL,
  email VARCHAR(250) DEFAULT NULL
);