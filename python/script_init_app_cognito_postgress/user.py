from sqlalchemy.ext.declarative import AbstractConcreteBase, declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, FetchedValue
from sqlalchemy.types import String, Boolean


Base = declarative_base()


class User(Base, AbstractConcreteBase):
    __table_args__ = {'schema': 'public'}
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), FetchedValue(), primary_key=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    admin = Column(Boolean, nullable=False)

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.admin is True
