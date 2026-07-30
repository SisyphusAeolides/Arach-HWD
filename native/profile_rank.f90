module arach_hwd_profile_rank
  use, intrinsic :: iso_c_binding, only: c_double, c_int
  implicit none
contains
  function arach_hwd_rank(features, count) result(score) bind(C)
    real(c_double), intent(in) :: features(*)
    integer(c_int), value, intent(in) :: count
    real(c_double) :: score

    if (count /= 3_c_int) then
      score = -1.0_c_double
      return
    end if
    score = max(features(1), 0.0_c_double) * 4.0_c_double &
          + max(features(2), 0.0_c_double) * 2.0_c_double &
          + max(features(3), 0.0_c_double)
  end function arach_hwd_rank
end module arach_hwd_profile_rank
