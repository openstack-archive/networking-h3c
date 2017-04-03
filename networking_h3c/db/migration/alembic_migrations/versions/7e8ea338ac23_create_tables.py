# Copyright 2016 Hangzhou H3C Technologies Co. Ltd.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Create tables

Revision ID: 7e8ea338ac23
Revises: None
Create Date: 2016-12-28 09:42:46.276856

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7e8ea338ac23'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('h3c_servicecontexts',
                    sa.Column('id', sa.String(36), primary_key=True),
                    sa.Column('tenant_id', sa.String(255)),
                    sa.Column('name', sa.String(255)),
                    sa.Column('description', sa.String(255)),
                    sa.Column('type', sa.Enum('router', 'network',
                                              'subnet', 'port'),
                              nullable=False),
                    sa.Column('in_chain', sa.Boolean)
                    )
    op.create_table('h3c_serviceinsertions',
                    sa.Column('id', sa.String(36), primary_key=True),
                    sa.Column('tenant_id', sa.String(255),
                              nullable=True),
                    sa.Column('name', sa.String(255)),
                    sa.Column('source_context_type', sa.String(255),
                              nullable=True),
                    sa.Column('source_context_id', sa.String(255),
                              nullable=True),
                    sa.Column('destination_context_type', sa.String(255),
                              nullable=True),
                    sa.Column('destination_context_id', sa.String(255),
                              nullable=True)
                    )
    op.create_table('h3c_servicenodes',
                    sa.Column('id', sa.String(36), primary_key=True),
                    sa.Column('tenant_id', sa.String(255)),
                    sa.Column('service_type', sa.String(255)),
                    sa.Column('service_instance_id', sa.String(255)),
                    sa.Column('insertion_id', sa.String(255),
                              sa.ForeignKey('h3c_serviceinsertions.id',
                                            ondelete='CASCADE')),
                    )
    op.create_table('h3c_loadbalancers',
                    sa.Column('id', sa.String(36), primary_key=True),
                    sa.Column('tenant_id', sa.String(255)),
                    sa.Column('pool_id', sa.String(255)),
                    sa.Column('name', sa.String(255)),
                    sa.Column('description', sa.String(255)),
                    sa.Column('mode', sa.Enum('GATEWAY', 'SERVICE_CHAIN',
                                              'VIP_ROUTE', 'CGSR'),
                              nullable=False)
                    )
    op.create_table('h3c_l3_vxlan_allocations',
                    sa.Column('vxlan_vni', sa.Integer, nullable=False,
                              primary_key=True, autoincrement=False),
                    sa.Column('router_id', sa.String(255)),
                    sa.Column('allocated', sa.Boolean, nullable=False,
                              default=False, server_default=sa.sql.false(),
                              index=True),
                    )
