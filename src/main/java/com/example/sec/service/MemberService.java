package com.example.sec.service;

import com.example.sec.dto.MemberDto;
import com.example.sec.model.MemberEntity;
import com.example.sec.model.Role;
import com.example.sec.repo.MemberRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sun.java2d.pipe.SpanShapeRenderer;

import java.lang.reflect.Member;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class MemberService implements UserDetailsService {

    private MemberRepository repository;

    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        Optional<MemberEntity> memberEntityWrapper = repository.findByEmail(userEmail);
        MemberEntity memberEntity = memberEntityWrapper.get();

        List<GrantedAuthority> authorities = new ArrayList<>();

        if ("admin@example.com".equals(userEmail)) {
            authorities.add(new SimpleGrantedAuthority(Role.ADMIN.getValue()));
        } else {
            authorities.add(new SimpleGrantedAuthority(Role.MEMBER.getValue()));
        }

        return new User(memberEntity.getEmail(), memberEntity.getPassword(), authorities);
    }

    @Transactional
    public Long joinUser(MemberDto dto) {
        // 비밀번호 암호화
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        dto.setPassword(passwordEncoder.encode(dto.getPassword()));

        return repository.save(dto.toEntity()).getId();
    }
}
