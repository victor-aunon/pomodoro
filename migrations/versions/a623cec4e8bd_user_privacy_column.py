"""user privacy column

Revision ID: a623cec4e8bd
Revises: c4bba5a5994c
Create Date: 2019-05-01 20:31:10.577686

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a623cec4e8bd'
down_revision = 'c4bba5a5994c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('privacy', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'privacy')
    # ### end Alembic commands ###
