SET ROLE 'aiohttpdemo_user';

BEGIN;
--
-- Create model Choice
--
CREATE TABLE "choice" ("id" serial NOT NULL PRIMARY KEY, "choice_text" varchar(200) NOT NULL, "votes" integer NOT NULL);
--
-- Create model Question
--
CREATE TABLE "question" ("id" serial NOT NULL PRIMARY KEY, "question_text" varchar(200) NOT NULL, "pub_date" timestamp with time zone NOT NULL);
--
-- Add field question to choice
--
ALTER TABLE "choice" ADD COLUMN "question_id" integer NOT NULL;
ALTER TABLE "choice" ALTER COLUMN "question_id" DROP DEFAULT;
CREATE INDEX "choice_7aa0f6ee" ON "choice" ("question_id");
ALTER TABLE "choice" ADD CONSTRAINT "choice_question_id_c5b4b260_fk_question_id" FOREIGN KEY ("question_id") REFERENCES "question" ("id") DEFERRABLE INITIALLY DEFERRED;

COMMIT;
