INSERT INTO users(login, password, roles)
VALUES
       ('admin', '$2a$10$ctPFhgJh.YIE21AA0OGl5er3p9f3XsAwkmTXnP2I7BxCpQbr1QAg2', '{"ADMIN", "USER"}'),
       ('user', '$2a$10$ctPFhgJh.YIE21AA0OGl5er3p9f3XsAwkmTXnP2I7BxCpQbr1QAg2', '{"USER"}');

INSERT INTO cards (number, balance, issuer, holder, user_id, status)
VALUES ('1234', 1000000, 'Visa', 'user1', 1, 'ACTIVE'),
       ('2345', 1000000, 'Visa', 'user2', 2, 'ACTIVE'),
       ('2345', 1000000, 'MasterCard', 'user2', 2, 'ACTIVE');

