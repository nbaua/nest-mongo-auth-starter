import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { User } from './interfaces/user.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User') private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<any> {
    const user = await this.userModel.findOne({
      username: authCredentialsDto.username,
    });

    if (user) {
      return {
        success: false,
        message: 'Username already exists.',
      };
    } else {
      const hashedPassword = await bcrypt.hash(authCredentialsDto.password, 9);
      this.userModel.create({
        username: authCredentialsDto.username,
        password: hashedPassword,
      });
      return {
        success: true,
        message: 'User account created.',
      };
    }
  }

  async signIn(authCredentialsDto: AuthCredentialsDto) {
    const user = await this.userModel.findOne({
      username: authCredentialsDto.username,
    });
    if (!user) {
      return {
        success: false,
        message: 'username does not exists',
      };
    } else {
      const valid = await this.validateUser(
        authCredentialsDto.password,
        user.password,
      );
      if (valid) {
        const payload = { username: user.username, sub: user._id };
        return {
          success: true,
          accessToken: this.jwtService.sign(payload),
        };
      } else {
        return {
          success: false,
          message: 'Invalid credentials.',
        };
      }
    }
  }

  async validateUser(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }
}
