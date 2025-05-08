import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../../database/entities/user.entity';
import { HashService } from '../hash/hash.service';
import { HashModule } from '../hash/hash.module';
import { UserService } from './user.service';

@Module({
  imports: [TypeOrmModule.forFeature([UserEntity]), HashModule],
  providers: [UserService, HashService],
  exports: [UserService, TypeOrmModule],
})
export class UserModule {}
