import { JwtService } from '@nestjs/jwt';
/*
https://docs.nestjs.com/guards#guards
*/

import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { JwtPayload } from '../interfaces/jwt.payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private JwtService: JwtService,private authServices:AuthService) {}

  async canActivate(context: ExecutionContext):  Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    // console.log(request);
    const token = this.extractTokenFromHeader(request);
    // console.log({token});
    if (!token) {
      throw new UnauthorizedException('There is no bearer token');
    }

    try {
      const payload = await this.JwtService.verifyAsync<JwtPayload>(
        token,
        {secret: process.env.JWT_SEED},
      );

      

      const user = await this.authServices.findUserById(payload.id);

      console.log(user);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      if (!user.isActive) {
        throw new UnauthorizedException('User not active');
      }
  
      request['user'] = user;




    } catch (err) {
      // console.log(err);
      throw new UnauthorizedException('Invalid token');
    }

    

    // const decoded = this.JwtService.verify(token);
    // console.log(decoded);
    return true;
  }

  private extractTokenFromHeader(request: Request): string|undefined {
    const [type, token] = request.headers['authorization']?.split(' ') || [];
    
    return type === 'Bearer' && token ? token : undefined;
  }
}
