const express = require('express');
const passport = require('passport');
const bcrypt = require('bcrypt');
const { isLoggedIn, isNotLoggedIn } = require('./middlewares');
const User = require('../models/user');

const router = express.Router();

router.post('/join', isNotLoggedIn, async (req, res, next) => {
  const { email, nick, password } = req.body;
  try {
    // 이미 존재하는 사용자인지 db에서 가져온다.
    const exUser = await User.findOne({ where: { email } });
    if (exUser) {
      // 만약 이미 존재하는 사용자라면 회원가입 페이지로 되돌려보내는데 뒤에 쿼리 스트링을 포함 시킨다.
      return res.redirect('/join?error=exist');
    }
    // 비밀번호를 암호화 한다.
    const hash = await bcrypt.hash(password, 12);
    // 회원 정보를 저장하고 메인 페이지로 redirect 한다.
    await User.create({
      email,
      nick,
      password: hash,
    });
    return res.redirect('/');
  } catch (error) {
    console.error(error);
    return next(error);
  }
});

router.post('/login', isNotLoggedIn, (req, res, next) => {
  // 로그인 요청이 들어오면 passport 미들웨어가 로컬 로그인 전략을 수행한다.
  // 미들웨어인데 라우터 미들웨어 안에 있는 이유는 미들웨어에 사용자 정의 기능을 추가하고 싶을 때 이렇게 한다.
  passport.authenticate('local', (authError, user, info) => {
    if (authError) {
      console.error(authError);
      return next(authError);
    }
    if (!user) {
      return res.redirect(`/?loginError=${info.message}`);
    }
    // 두 번째 매개변수가 있으면 로그인 성공
    return req.login(user, (loginError) => {
      if (loginError) {
        console.error(loginError);
        return next(loginError);
      }
      return res.redirect('/');
    });
  })(req, res, next);
});

router.get('/logout', isLoggedIn, (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

router.get('/kakao', passport.authenticate('kakao'));

router.get(
  '/kakao/callback',
  passport.authenticate('kakao', {
    failureRedirect: '/',
  }),
  (req, res) => {
    res.redirect('/');
  }
);

module.exports = router;
