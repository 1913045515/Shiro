package com.shiro.test1.core.service;


import com.shiro.test1.core.bean.UserInfo;

import java.util.List;

public interface UserInfoService {
	
	/**通过username查找用户信息;*/
	public UserInfo findByUsername(String username);

	public List<UserInfo> findAllUser();
}
