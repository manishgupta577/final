
import { joiValidation } from '@global/decorators/joi-validation.decorator';
import { Request, Response } from 'express';
import { config } from '@root/config';
import JWT from 'jsonwebtoken';
import HTTP_STATUS from 'http-status-codes';
import { authService } from '@service/db/auth.service';
import { loginSchema } from '@auth/schemes/signin';
import { IAuthDocument } from '@auth/interfaces/auth.interface';
import { BadRequestError } from '@global/helpers/error-handler';
import { userService } from '@service/db/user.service';
import { IResetPasswordParams, IUserDocument } from '@user/interfaces/user.interface';
import { mailTransport } from '@service/emails/mail.transport';
import { resetPasswordTemplate } from '@service/emails/templates/reset-password/reset-password-template';
import { forgotPasswordTemplate } from '@service/emails/templates/forgot-password/forgot-password-template';
import { emailQueue } from '@service/queues/email.queue';
import moment from 'moment';
import publicIP from 'ip';

export class SignIn {
  @joiValidation(loginSchema)
  public async read(req: Request, res: Response): Promise<void> {
    const { username, password } = req.body;
    const existingUser: IAuthDocument = await authService.getAuthUserByUsername(username);
    if (!existingUser) {
      throw new BadRequestError('Invalid credentials');
    }

    const passwordsMatch: boolean = await existingUser.comparePassword(password);
    if (!passwordsMatch) {
      throw new BadRequestError('Invalid credentials');
    }
    // console.log('dckjcjdnc',existingUser);
    const user: IUserDocument = await userService.getUserByAuthId(`${existingUser._id}`);

    const userJwt: string = JWT.sign(
      {
        userId: existingUser._id,
        uId: existingUser.uId,
        email: existingUser.email,
        username: existingUser.username,
        avatarColor: existingUser.avatarColor
      },
      config.JWT_TOKEN!
    );
    // await mailTransport.sendEmail('mack77@ethereal.email','Testing development email','this is atest email');
    // const templateParams : IResetPasswordParams ={
    //     username:existingUser.username!,
    //     email:existingUser.email!,
    //     ipaddress:publicIP.address(),
    //     date:moment().format('DD/MM/YYYY HH:mm')
    // };
    // const resetLink = `${config.CLIENT_URL}/reset-password?=1234567898373`;
    // const template: string  = resetPasswordTemplate.passwordResetConfirmationTemplate(templateParams);
    // emailQueue.addEmailJob('forgotPasswordEmail',{template,receiverEmail:'tatum94@ethereal.email',subject:'Password reset confirmation'});


    req.session = { jwt: userJwt };
    // const userDocument: IUserDocument = {
    //   ...user,
    //   authId: existingUser!._id,
    //   username: existingUser!.username,
    //   email: existingUser!.email,
    //   avatarColor: existingUser!.avatarColor,
    //   uId: existingUser!.uId,
    //   createdAt: existingUser!.createdAt
    // } as IUserDocument;
    res.status(HTTP_STATUS.OK).json({ message: 'User login successfully', user: existingUser, token: userJwt });
  }
}
