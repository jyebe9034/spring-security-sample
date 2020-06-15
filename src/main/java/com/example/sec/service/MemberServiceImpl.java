package com.example.sec.service;

import com.example.sec.dto.MemberDto;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@AllArgsConstructor
public class MemberServiceImpl implements UserDetailsService, MemberService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }

    @Override
    @Transactional
    public Long joinUser(MemberDto dto) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


        return null;
    }
}
