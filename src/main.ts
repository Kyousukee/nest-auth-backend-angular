import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors();


  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,


    })
  );

  const PORT = process.env.PORT ?? 3000;

  console.log('🚀 Application is running on:' + PORT);

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
