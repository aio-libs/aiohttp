.. _tutorial-database:

Database
========

Setup
-----

In this tutorial we use latest PostgreSQL database.
You can install PostgreSQL using this instruction http://www.postgresql.org/download/

Database schema
---------------
We use SQLAlchemy for describe database schema.
For this tutorial we can use two simple models `question` and `choice`. ::

    import sqlalchemy as sa

    meta = sa.MetaData()

    question = sa.Table(
        'question', meta,
        sa.Column('id', sa.Integer, nullable=False),
        sa.Column('question_text', sa.String(200), nullable=False),
        sa.Column('pub_date', sa.Date, nullable=False),

        # Indexes #
        sa.PrimaryKeyConstraint('id', name='question_id_pkey'))

    choice = sa.Table(
        'choice', meta,
        sa.Column('id', sa.Integer, nullable=False),
        sa.Column('question_id', sa.Integer, nullable=False),
        sa.Column('choice_text', sa.String(200), nullable=False),
        sa.Column('votes', sa.Integer, server_default="0", nullable=False),

        # Indexes #
        sa.PrimaryKeyConstraint('id', name='choice_id_pkey'),
        sa.ForeignKeyConstraint(['question_id'], [question.c.id],
                                name='choice_question_id_fkey',
                                ondelete='CASCADE'),
    )



You can find below description of tables in database:

First table is question:

+---------------+
| question      |
+===============+
| id            |
+---------------+
| question_text |
+---------------+
| pub_date      |
+---------------+

and second table is choice table:

+---------------+
| choice        |
+===============+
| id            |
+---------------+
| choice_text   |
+---------------+
| votes         |
+---------------+
| question_id   |
+---------------+
