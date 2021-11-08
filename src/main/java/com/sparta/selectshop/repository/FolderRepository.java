package com.sparta.selectshop.repository;

import com.sparta.selectshop.domain.Folder;
import com.sparta.selectshop.domain.Product;
import com.sparta.selectshop.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface FolderRepository extends JpaRepository<Folder, Long> {
    List<Folder> findAllByUser(User user);

    List<Folder> findAllByUserAndNameIn(User user, List<String> name);

    Folder findByName(String name);
}