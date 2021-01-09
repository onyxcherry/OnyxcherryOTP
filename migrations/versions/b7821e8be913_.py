"""empty message

Revision ID: b7821e8be913
Revises: 199b46727f51
Create Date: 2021-01-08 21:04:34.309278

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b7821e8be913"
down_revision = "199b46727f51"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("webauthn", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("user_identifier", sa.String(length=86), nullable=True)
        )

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("webauthn", schema=None) as batch_op:
        batch_op.drop_column("user_identifier")

    # ### end Alembic commands ###