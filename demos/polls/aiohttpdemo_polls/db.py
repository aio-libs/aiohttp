import asyncio
import sqlalchemy as sa


__all__ = ['question', 'choice']

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


class RecordNotFound(Exception):
    """Requested record in database was not found"""


@asyncio.coroutine
def get_question(postgres, question_id):
    with (yield from postgres) as conn:
        cursor = yield from conn.execute(
            question.select()
            .where(question.c.id == question_id))
        question_record = yield from cursor.first()
        if not question_record:
            msg = "Question with id: {} does not exists"
            raise RecordNotFound(msg.format(question_id))
        cursor = yield from conn.execute(
            choice.select()
            .where(choice.c.question_id == question_id)
            .order_by(choice.c.id))
        choice_recoreds = yield from cursor.fetchall()
    return question_record, choice_recoreds


@asyncio.coroutine
def vote(postgres, question_id, choice_id):
    with (yield from postgres) as conn:
        resp = yield from conn.execute(
            choice.update()
            .returning(*choice.c)
            .where(choice.c.question_id == question_id)
            .where(choice.c.id == choice_id)
            .values(votes=choice.c.votes + 1))
        record = yield from resp.fetchone()
        if not record:
            msg = "Question with id: {} or choice id: {} does not exists"
            raise RecordNotFound(msg.format(question_id), choice_id)
