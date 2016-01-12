SET ROLE 'aiohttpdemo_user';

INSERT INTO question (id, question_text, pub_date) VALUES (1, 'What''s new?', '2015-12-15 17:17:49.629+02');


--
-- Name: question_id_seq; Type: SEQUENCE SET; Schema: public; Owner: polls
--

SELECT pg_catalog.setval('question_id_seq', 1, true);


INSERT INTO choice (id, choice_text, votes, question_id) VALUES (1, 'Not much', 0, 1);
INSERT INTO choice (id, choice_text, votes, question_id) VALUES (2, 'The sky', 0, 1);
INSERT INTO choice (id, choice_text, votes, question_id) VALUES (3, 'Just hacking again', 0, 1);


--
-- Name: choice_id_seq; Type: SEQUENCE SET; Schema: public; Owner: polls
--

SELECT pg_catalog.setval('choice_id_seq', 3, true);
