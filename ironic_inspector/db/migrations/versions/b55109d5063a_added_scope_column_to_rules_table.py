# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Added 'scope' column to 'Rules' table

Revision ID: b55109d5063a
Revises: bf8dec16023c
Create Date: 2019-12-11 14:15:57.510289

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b55109d5063a'
down_revision = 'bf8dec16023c'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('rules', sa.Column('scope', sa.String(255),
                                     nullable=True, default=None))
