"""empty message

Revision ID: 8c92e57fc90b
Revises: 
Create Date: 2024-07-03 23:28:39.079298

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8c92e57fc90b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('level', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('level')
    )
    op.create_table('tasks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('reward', sa.Float(), nullable=False),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=True),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('phone', sa.String(length=20), nullable=True),
    sa.Column('image', sa.String(length=1000), nullable=True),
    sa.Column('password', sa.String(length=500), nullable=False),
    sa.Column('withdrawal_password', sa.String(length=500), nullable=False),
    sa.Column('tier', sa.String(length=50), nullable=False),
    sa.Column('balance', sa.Float(), nullable=True),
    sa.Column('admin', sa.Boolean(), nullable=True),
    sa.Column('gender', sa.String(length=50), nullable=True),
    sa.Column('about', sa.String(length=5000), nullable=True),
    sa.Column('verified', sa.Boolean(), nullable=True),
    sa.Column('ip', sa.String(length=50), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_users_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_users_phone'), ['phone'], unique=True)

    op.create_table('accountdetails',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('account_type', sa.Enum('EXCHANGE', 'REVOLUT', 'WISE', name='accounttype'), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('phone', sa.String(length=20), nullable=True),
    sa.Column('exchange', sa.String(length=100), nullable=True),
    sa.Column('exchange_address', sa.String(length=255), nullable=True),
    sa.Column('bank_account', sa.String(length=50), nullable=True),
    sa.Column('short_code', sa.String(length=20), nullable=True),
    sa.Column('link', sa.String(length=255), nullable=True),
    sa.Column('wise_email', sa.String(length=100), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('notiications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=128), nullable=True),
    sa.Column('image', sa.String(length=128), nullable=True),
    sa.Column('message', sa.String(length=255), nullable=False),
    sa.Column('file_path', sa.String(length=255), nullable=True),
    sa.Column('is_read', sa.Boolean(), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('notiications', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_notiications_image'), ['image'], unique=False)
        batch_op.create_index(batch_op.f('ix_notiications_title'), ['title'], unique=False)

    op.create_table('orders',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('task_id', sa.Integer(), nullable=False),
    sa.Column('amount', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('rating', sa.Integer(), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['task_id'], ['tasks.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('payments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('txn_ref', sa.String(length=100), nullable=True),
    sa.Column('txn_amt', sa.Integer(), nullable=True),
    sa.Column('txn_desc', sa.String(length=100), nullable=True),
    sa.Column('txn_status', sa.String(length=100), nullable=True),
    sa.Column('currency_code', sa.String(length=100), nullable=True),
    sa.Column('provider', sa.String(length=100), nullable=True),
    sa.Column('deleted', sa.Boolean(), nullable=True),
    sa.Column('created', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id')
    )
    op.create_table('user_roles',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_roles')
    op.drop_table('payments')
    op.drop_table('orders')
    with op.batch_alter_table('notiications', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notiications_title'))
        batch_op.drop_index(batch_op.f('ix_notiications_image'))

    op.drop_table('notiications')
    op.drop_table('accountdetails')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_phone'))
        batch_op.drop_index(batch_op.f('ix_users_name'))
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    op.drop_table('tasks')
    op.drop_table('roles')
    # ### end Alembic commands ###
