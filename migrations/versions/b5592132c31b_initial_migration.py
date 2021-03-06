"""initial migration

Revision ID: b5592132c31b
Revises: 
Create Date: 2020-08-28 09:44:46.123174

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b5592132c31b"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("email", sa.String(length=120), nullable=True),
        sa.Column("password_hash", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_user_email"), "user", ["email"], unique=True)
    op.create_index(
        op.f("ix_user_username"), "user", ["username"], unique=True
    )
    op.create_table(
        "otp",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("secret", sa.String(length=32), nullable=True),
        sa.Column("is_valid", sa.Boolean(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("remaining_attempts", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "reset_password_value",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("first_value", sa.String(length=32), nullable=True),
        sa.Column("first_date", sa.DateTime(), nullable=True),
        sa.Column("second_value", sa.String(length=32), nullable=True),
        sa.Column("second_date", sa.DateTime(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("reset_password_value")
    op.drop_table("otp")
    op.drop_index(op.f("ix_user_username"), table_name="user")
    op.drop_index(op.f("ix_user_email"), table_name="user")
    op.drop_table("user")
    # ### end Alembic commands ###
