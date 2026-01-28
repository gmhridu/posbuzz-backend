import { ApiProperty } from '@nestjs/swagger';

export class AuthTokensDto {
  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'JWT access token (15 minutes)',
  })
  accessToken: string;

  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'JWT refresh token (7 days)',
  })
  refreshToken: string;
}

export class UserResponseDto {
  @ApiProperty({
    example: 'clxxx1234567890',
    description: 'User ID',
  })
  id: string;

  @ApiProperty({
    example: 'John Doe',
    description: 'User full name',
  })
  name: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'User email',
  })
  email: string;

  @ApiProperty({
    example: '2024-01-27T12:00:00.000Z',
    description: 'Account creation timestamp',
  })
  createdAt: Date;

  @ApiProperty({
    example: '2024-01-27T12:00:00.000Z',
    description: 'Account last update timestamp',
  })
  updatedAt: Date;
}

export class AuthResponseDto {
  @ApiProperty({
    type: UserResponseDto,
    description: 'User details',
  })
  user: UserResponseDto;

  @ApiProperty({
    type: AuthTokensDto,
    description: 'Authentication tokens',
  })
  tokens: AuthTokensDto;
}
