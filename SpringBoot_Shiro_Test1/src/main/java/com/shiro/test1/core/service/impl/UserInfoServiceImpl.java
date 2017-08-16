package com.shiro.test1.core.service.impl;
import com.shiro.test1.core.bean.UserInfo;
import com.shiro.test1.core.repository.UserInfoRepository;
import com.shiro.test1.core.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Service
public class UserInfoServiceImpl implements UserInfoService {
	@Autowired
	private UserInfoRepository userInfoRepository;

	@Override
	public List<UserInfo> findAllUser() {
		System.out.println("UserInfoServiceImpl.findAllUser()");
		List<UserInfo> list=new ArrayList<>();
		Iterator<UserInfo> it=userInfoRepository.findAll().iterator();
		while(it.hasNext()){
			list.add(it.next());
		}
		return list;
	}
	
	@Override
	public UserInfo findByUsername(String username) {
		System.out.println("UserInfoServiceImpl.findByUsername()");
		return userInfoRepository.findByUsername(username);
	}
	
}
