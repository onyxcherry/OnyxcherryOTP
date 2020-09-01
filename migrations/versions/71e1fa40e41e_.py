"""empty message

Revision ID: 71e1fa40e41e
Revises: b5592132c31b
Create Date: 2020-08-28 20:28:05.755138

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "71e1fa40e41e"
down_revision = "b5592132c31b"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "reset_password",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("first_value", sa.String(length=32), nullable=True),
        sa.Column("first_date", sa.DateTime(), nullable=True),
        sa.Column("second_value", sa.String(length=32), nullable=True),
        sa.Column("second_date", sa.DateTime(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    op.drop_table("reset_password_value")
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "reset_password_value",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column(
            "first_value",
            sa.VARCHAR(length=32),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "first_date",
            postgresql.TIMESTAMP(),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "second_value",
            sa.VARCHAR(length=32),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "second_date",
            postgresql.TIMESTAMP(),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column("user_id", sa.INTEGER(), autoincrement=False, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="reset_password_value_user_id_fkey"
        ),
        sa.PrimaryKeyConstraint("id", name="reset_password_value_pkey"),
    )
    op.drop_table("reset_password")
    # ### end Alembic commands ###